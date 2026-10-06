// Package zones models firewall zones and inter-zone policies and renders them as an nftables script.
package zones

import (
	"fmt"
	"net/netip"
	"regexp"
	"sort"
	"strconv"
	"strings"
)

const (
	InputRestricted = "restricted"
	InputAccept     = "accept"

	ModeAllow   = "allow"
	ModeLimited = "limited"

	maxCustomPorts = 512
)

var (
	namePattern  = regexp.MustCompile(`^[a-z][a-z0-9_-]{0,15}$`)
	ifacePattern = regexp.MustCompile(`^[A-Za-z0-9_.:-]{1,15}$`)
)

// Port is a protocol with an inclusive port range. To optionally translates
// a single port (policies only) to "80" or "10.0.0.5:80"; Comment is a free note.
type Port struct {
	Proto   string `json:"proto"`
	Start   int    `json:"start"`
	End     int    `json:"end"`
	To      string `json:"to,omitempty"`
	Comment string `json:"comment,omitempty"`
}

func (p Port) String() string {
	if p.Start == p.End {
		return fmt.Sprintf("%s/%d", p.Proto, p.Start)
	}
	return fmt.Sprintf("%s/%d-%d", p.Proto, p.Start, p.End)
}

// Access lists what is reachable: named services plus explicit ports.
// ServiceNAT maps a service name to its translation target.
type Access struct {
	Services   []string          `json:"services,omitempty"`
	Ports      []Port            `json:"ports,omitempty"`
	ServiceNAT map[string]string `json:"service_nat,omitempty"`
}

// Target is where translated traffic goes: a port, optionally on a specific address.
type Target struct {
	Addr netip.Addr
	Port int
}

// ParseTarget accepts "80", "10.0.0.5:80" or "[2001:db8::5]:80".
func ParseTarget(text string) (Target, error) {
	text = strings.TrimSpace(text)
	if port, err := strconv.Atoi(text); err == nil {
		if port < 1 || port > 65535 {
			return Target{}, fmt.Errorf("ungültiger NAT-Port %q", text)
		}
		return Target{Port: port}, nil
	}
	addrPort, err := netip.ParseAddrPort(text)
	if err != nil || addrPort.Port() == 0 {
		return Target{}, fmt.Errorf("ungültiges NAT-Ziel %q: erwartet wird Port oder IP:Port", text)
	}
	return Target{Addr: addrPort.Addr(), Port: int(addrPort.Port())}, nil
}

// CanTranslate reports whether a service has one port number, so a single target is unambiguous.
func CanTranslate(service string) bool {
	ports := catalog[service]
	if len(ports) == 0 {
		return false
	}
	for _, port := range ports {
		if port.Start != port.End || port.Start != ports[0].Start {
			return false
		}
	}
	return true
}

// ServiceDetail describes a service's ports, e.g. "udp 123".
func ServiceDetail(service string) string {
	if service == PingService {
		return "ICMP Echo"
	}
	parts := make([]string, 0, len(catalog[service]))
	for _, port := range catalog[service] {
		parts = append(parts, fmt.Sprintf("%s %d", port.Proto, port.Start))
	}
	return strings.Join(parts, ", ")
}

// Zone groups interfaces and defines what the host itself accepts from them.
type Zone struct {
	Name       string   `json:"name"`
	Interfaces []string `json:"interfaces"`
	Input      string   `json:"input"`
	// Isolated blocks traffic between interfaces of the same zone.
	Isolated bool `json:"isolated"`
	// Ping is the legacy flag; Load turns it into the "ping" service.
	Ping bool `json:"ping,omitempty"`
	Access
}

// Policy controls forwarded traffic from one zone to another. Absent policy means blocked.
type Policy struct {
	From       string `json:"from"`
	To         string `json:"to"`
	Mode       string `json:"mode"`
	Masquerade bool   `json:"masquerade"`
	Access
}

type Config struct {
	Zones    []Zone   `json:"zones"`
	Policies []Policy `json:"policies"`
}

// Ping is a pseudo-service: ICMP echo has no port.
const PingService = "ping"

func single(proto string, port int) Port { return Port{Proto: proto, Start: port, End: port} }

var catalog = map[string][]Port{
	PingService: {},
	"ssh":       {single("tcp", 22)},
	"http":      {single("tcp", 80)},
	"https":     {single("tcp", 443)},
	"dns":       {single("tcp", 53), single("udp", 53)},
	"dhcp":      {single("udp", 67)},
	"dhcpv6":    {single("udp", 547)},
	"ntp":       {single("udp", 123)},
	"nfs":       {single("tcp", 2049)},
	"smb":       {single("tcp", 139), single("tcp", 445)},
	"mdns":      {single("udp", 5353)},
	"wireguard": {single("udp", 51820)},
	"swat":      {single("tcp", 8443)},
}

// ServiceNames returns the known service names in stable order.
func ServiceNames() []string {
	names := make([]string, 0, len(catalog))
	for name := range catalog {
		names = append(names, name)
	}
	sort.Strings(names)
	return names
}

// ParsePorts parses comma or space separated entries like "tcp/443" or "udp/8000-8100".
func ParsePorts(text string) ([]Port, error) {
	var ports []Port
	for _, field := range strings.FieldsFunc(text, func(r rune) bool { return r == ',' || r == ' ' || r == '\n' }) {
		proto, rangeText, ok := strings.Cut(field, "/")
		if !ok || (proto != "tcp" && proto != "udp") {
			return nil, fmt.Errorf("ungültiger Port %q, erwartet wird tcp/443 oder udp/8000-8100", field)
		}
		startText, endText, isRange := strings.Cut(rangeText, "-")
		start, err := strconv.Atoi(startText)
		end := start
		if err == nil && isRange {
			end, err = strconv.Atoi(endText)
		}
		if err != nil || start < 1 || end > 65535 || start > end {
			return nil, fmt.Errorf("ungültiger Port %q", field)
		}
		ports = append(ports, Port{Proto: proto, Start: start, End: end})
	}
	return ports, nil
}

// HasService reports whether the named service is selected.
func (a Access) HasService(name string) bool {
	for _, service := range a.Services {
		if service == name {
			return true
		}
	}
	return false
}

func (a Access) resolve() []Port {
	ports := append([]Port(nil), a.Ports...)
	for _, name := range a.Services {
		ports = append(ports, catalog[name]...)
	}
	return ports
}

// entry is one reachable port and, if set, where it is translated to.
type entry struct {
	Port   Port
	Target *Target
}

func (a Access) entries() []entry {
	var result []entry
	for _, port := range a.Ports {
		item := entry{Port: port}
		if target, err := ParseTarget(port.To); port.To != "" && err == nil {
			item.Target = &target
		}
		result = append(result, item)
	}
	for _, name := range a.Services {
		for _, port := range catalog[name] {
			item := entry{Port: port}
			if target, err := ParseTarget(a.ServiceNAT[name]); a.ServiceNAT[name] != "" && err == nil {
				item.Target = &target
			}
			result = append(result, item)
		}
	}
	return result
}

// HasTranslation reports whether any port is translated.
func (a Access) HasTranslation() bool {
	for _, item := range a.entries() {
		if item.Target != nil {
			return true
		}
	}
	return false
}

func (a Access) validate(allowNAT bool) error {
	if len(a.Ports) > maxCustomPorts {
		return fmt.Errorf("zu viele eigene Ports (maximal %d)", maxCustomPorts)
	}
	for _, name := range a.Services {
		if _, ok := catalog[name]; !ok {
			return fmt.Errorf("unbekannter Dienst %q", name)
		}
	}
	for _, port := range a.Ports {
		if (port.Proto != "tcp" && port.Proto != "udp") || port.Start < 1 || port.End > 65535 || port.Start > port.End {
			return fmt.Errorf("ungültiger Port %s", port)
		}
		if port.To == "" {
			continue
		}
		if !allowNAT {
			return fmt.Errorf("NAT-Ports sind nur in Richtlinien möglich")
		}
		if port.Start != port.End {
			return fmt.Errorf("Port %s: Übersetzung ist nur für einzelne Ports möglich", port)
		}
		if _, err := ParseTarget(port.To); err != nil {
			return err
		}
	}
	for name, target := range a.ServiceNAT {
		if !allowNAT {
			return fmt.Errorf("NAT-Ports sind nur in Richtlinien möglich")
		}
		selected := false
		for _, service := range a.Services {
			selected = selected || service == name
		}
		if !selected || !CanTranslate(name) {
			return fmt.Errorf("Dienst %q kann nicht übersetzt werden", name)
		}
		if _, err := ParseTarget(target); err != nil {
			return err
		}
	}
	return nil
}

func (c Config) Zone(name string) (Zone, bool) {
	for _, zone := range c.Zones {
		if zone.Name == name {
			return zone, true
		}
	}
	return Zone{}, false
}

func (c Config) Policy(from, to string) (Policy, bool) {
	for _, policy := range c.Policies {
		if policy.From == from && policy.To == to {
			return policy, true
		}
	}
	return Policy{}, false
}

// Validate rejects anything that could produce an unsafe or ambiguous ruleset.
func (c Config) Validate() error {
	seenZones := make(map[string]bool)
	seenIfaces := make(map[string]string)
	for _, zone := range c.Zones {
		if !namePattern.MatchString(zone.Name) {
			return fmt.Errorf("ungültiger Zonenname %q: Kleinbuchstaben, Ziffern, _ und -, maximal 16 Zeichen", zone.Name)
		}
		if seenZones[zone.Name] {
			return fmt.Errorf("Zone %q ist doppelt vorhanden", zone.Name)
		}
		seenZones[zone.Name] = true
		if zone.Input != InputAccept && zone.Input != InputRestricted {
			return fmt.Errorf("Zone %q: ungültiger Eingangsmodus", zone.Name)
		}
		for _, iface := range zone.Interfaces {
			if !ifacePattern.MatchString(iface) {
				return fmt.Errorf("Zone %q: ungültiger Interface-Name %q", zone.Name, iface)
			}
			if other, dup := seenIfaces[iface]; dup {
				return fmt.Errorf("Interface %q ist bereits Zone %q zugeordnet", iface, other)
			}
			seenIfaces[iface] = zone.Name
		}
		if err := zone.Access.validate(false); err != nil {
			return fmt.Errorf("Zone %q: %w", zone.Name, err)
		}
	}
	seenPairs := make(map[string]bool)
	// The first matching DNAT rule wins, so one source zone may translate a port only once.
	translated := make(map[string]string)
	for _, policy := range c.Policies {
		for _, item := range policy.entries() {
			if item.Target == nil {
				continue
			}
			key := fmt.Sprintf("%s|%s|%d", policy.From, item.Port.Proto, item.Port.Start)
			if other, dup := translated[key]; dup {
				return fmt.Errorf("Port %s wird aus Zone %q bereits nach %q übersetzt", item.Port, policy.From, other)
			}
			translated[key] = policy.To
		}
	}
	for _, policy := range c.Policies {
		if !seenZones[policy.From] || !seenZones[policy.To] {
			return fmt.Errorf("Richtlinie %s→%s verweist auf eine unbekannte Zone", policy.From, policy.To)
		}
		if policy.From == policy.To {
			return fmt.Errorf("Richtlinie %s→%s: Verkehr innerhalb einer Zone wird über die Zone gesteuert", policy.From, policy.To)
		}
		if policy.Mode != ModeAllow && policy.Mode != ModeLimited {
			return fmt.Errorf("Richtlinie %s→%s: ungültiger Modus", policy.From, policy.To)
		}
		key := policy.From + ">" + policy.To
		if seenPairs[key] {
			return fmt.Errorf("Richtlinie %s→%s ist doppelt vorhanden", policy.From, policy.To)
		}
		seenPairs[key] = true
		if err := policy.Access.validate(true); err != nil {
			return fmt.Errorf("Richtlinie %s→%s: %w", policy.From, policy.To, err)
		}
		if policy.Mode == ModeLimited && len(policy.Services)+len(policy.Ports) == 0 {
			return fmt.Errorf("Richtlinie %s→%s: Modus „eingeschränkt“ braucht mindestens einen Dienst oder Port", policy.From, policy.To)
		}
	}
	return nil
}
