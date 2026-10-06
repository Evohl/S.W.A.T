package zones

import (
	"fmt"
	"sort"
	"strings"
)

// RemoveScript deletes the SWAT table; used for rollback when nothing was applied before.
const RemoveScript = "table inet swat\ndelete table inet swat\n"

func ifaceSet(names []string) string {
	quoted := make([]string, len(names))
	for i, name := range names {
		quoted[i] = `"` + name + `"`
	}
	return "{ " + strings.Join(quoted, ", ") + " }"
}

func (t Target) dnat() string {
	switch {
	case !t.Addr.IsValid():
		return fmt.Sprintf("dnat to :%d", t.Port)
	case t.Addr.Is4():
		return fmt.Sprintf("dnat ip to %s:%d", t.Addr, t.Port)
	default:
		return fmt.Sprintf("dnat ip6 to [%s]:%d", t.Addr, t.Port)
	}
}

// forwardMatch matches the packet after translation, when the forward chain sees it.
func (t Target) forwardMatch(proto string) string {
	match := fmt.Sprintf("%s dport %d", proto, t.Port)
	switch {
	case !t.Addr.IsValid():
		return match
	case t.Addr.Is4():
		return fmt.Sprintf("ip daddr %s %s", t.Addr, match)
	default:
		return fmt.Sprintf("ip6 daddr %s %s", t.Addr, match)
	}
}

// portRules merges overlapping and adjacent ranges per protocol so the sets stay minimal.
func portRules(ports []Port) []string {
	var rules []string
	for _, proto := range []string{"tcp", "udp"} {
		var ranges [][2]int
		for _, port := range ports {
			if port.Proto == proto {
				ranges = append(ranges, [2]int{port.Start, port.End})
			}
		}
		sort.Slice(ranges, func(i, j int) bool { return ranges[i][0] < ranges[j][0] })
		var merged [][2]int
		for _, r := range ranges {
			if last := len(merged) - 1; last >= 0 && r[0] <= merged[last][1]+1 {
				merged[last][1] = max(merged[last][1], r[1])
				continue
			}
			merged = append(merged, r)
		}
		items := make([]string, len(merged))
		for i, r := range merged {
			if r[0] == r[1] {
				items[i] = fmt.Sprint(r[0])
			} else {
				items[i] = fmt.Sprintf("%d-%d", r[0], r[1])
			}
		}
		if len(items) > 0 {
			rules = append(rules, fmt.Sprintf("%s dport { %s }", proto, strings.Join(items, ", ")))
		}
	}
	return rules
}

// Generate renders a validated config as an atomically replacing nftables script.
// Interfaces outside every zone are left untouched.
func Generate(cfg Config) (string, error) {
	if err := cfg.Validate(); err != nil {
		return "", err
	}
	if len(cfg.Zones) == 0 {
		return RemoveScript, nil
	}
	var b strings.Builder
	line := func(indent int, format string, args ...any) {
		b.WriteString(strings.Repeat("\t", indent))
		fmt.Fprintf(&b, format, args...)
		b.WriteByte('\n')
	}

	var zoned []string
	for _, zone := range cfg.Zones {
		zoned = append(zoned, zone.Interfaces...)
	}

	line(0, "# Managed-By: SWAT")
	line(0, "table inet swat")
	line(0, "delete table inet swat")
	line(0, "table inet swat {")

	line(1, "chain input {")
	line(2, "type filter hook input priority filter; policy accept;")
	line(2, "ct state established,related accept")
	line(2, "ct state invalid drop")
	line(2, `iifname "lo" accept`)
	for _, zone := range cfg.Zones {
		for _, iface := range zone.Interfaces {
			line(2, `iifname "%s" jump input_%s`, iface, zone.Name)
		}
	}
	line(1, "}")

	for _, zone := range cfg.Zones {
		line(1, "chain input_%s {", zone.Name)
		if zone.Input == InputAccept {
			line(2, "accept")
		} else {
			line(2, "icmpv6 type { nd-router-solicit, nd-router-advert, nd-neighbor-solicit, nd-neighbor-advert } accept")
			line(2, "udp sport 67 udp dport 68 accept")
			line(2, "udp sport 547 udp dport 546 accept")
			if zone.HasService(PingService) {
				line(2, "icmp type echo-request accept")
				line(2, "icmpv6 type echo-request accept")
			}
			for _, rule := range portRules(zone.resolve()) {
				line(2, "%s accept", rule)
			}
			line(2, "drop")
		}
		line(1, "}")
	}

	line(1, "chain forward {")
	line(2, "type filter hook forward priority filter; policy accept;")
	line(2, "ct state established,related accept")
	line(2, "ct state invalid drop")
	for _, policy := range cfg.Policies {
		from, _ := cfg.Zone(policy.From)
		to, _ := cfg.Zone(policy.To)
		if len(from.Interfaces) == 0 || len(to.Interfaces) == 0 {
			continue
		}
		match := fmt.Sprintf("iifname %s oifname %s", ifaceSet(from.Interfaces), ifaceSet(to.Interfaces))
		if policy.Mode == ModeAllow {
			line(2, `%s accept comment "%s>%s"`, match, policy.From, policy.To)
			continue
		}
		var plain []Port
		if policy.HasService(PingService) {
			line(2, `%s icmp type echo-request accept comment "%s>%s"`, match, policy.From, policy.To)
			line(2, `%s icmpv6 type echo-request accept comment "%s>%s"`, match, policy.From, policy.To)
		}
		for _, item := range policy.entries() {
			if item.Target == nil {
				plain = append(plain, item.Port)
				continue
			}
			line(2, `%s %s accept comment "%s>%s"`, match, item.Target.forwardMatch(item.Port.Proto), policy.From, policy.To)
		}
		for _, rule := range portRules(plain) {
			line(2, `%s %s accept comment "%s>%s"`, match, rule, policy.From, policy.To)
		}
	}
	for _, zone := range cfg.Zones {
		if !zone.Isolated && len(zone.Interfaces) > 1 {
			set := ifaceSet(zone.Interfaces)
			line(2, `iifname %s oifname %s accept comment "%s intern"`, set, set, zone.Name)
		}
	}
	if len(zoned) > 1 {
		set := ifaceSet(zoned)
		line(2, `iifname %s oifname %s drop comment "zwischen Zonen gesperrt"`, set, set)
	}
	line(1, "}")

	var natRules []string
	for _, policy := range cfg.Policies {
		from, _ := cfg.Zone(policy.From)
		if len(from.Interfaces) == 0 {
			continue
		}
		for _, item := range policy.entries() {
			if item.Target != nil {
				natRules = append(natRules, fmt.Sprintf(`iifname %s %s dport %d %s comment "%s>%s"`, ifaceSet(from.Interfaces), item.Port.Proto, item.Port.Start, item.Target.dnat(), policy.From, policy.To))
			}
		}
	}
	if len(natRules) > 0 {
		line(1, "chain prerouting {")
		line(2, "type nat hook prerouting priority dstnat; policy accept;")
		for _, rule := range natRules {
			line(2, "%s", rule)
		}
		line(1, "}")
	}

	line(1, "chain postrouting {")
	line(2, "type nat hook postrouting priority srcnat; policy accept;")
	for _, policy := range cfg.Policies {
		if !policy.Masquerade {
			continue
		}
		from, _ := cfg.Zone(policy.From)
		to, _ := cfg.Zone(policy.To)
		if len(from.Interfaces) == 0 || len(to.Interfaces) == 0 {
			continue
		}
		line(2, `iifname %s oifname %s masquerade comment "%s>%s"`, ifaceSet(from.Interfaces), ifaceSet(to.Interfaces), policy.From, policy.To)
	}
	line(1, "}")
	line(0, "}")
	return b.String(), nil
}
