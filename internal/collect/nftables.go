package collect

import (
	"bytes"
	"encoding/json"
	"fmt"
	"os/exec"
)

// Table is one nftables table (e.g. "inet firewalld").
type Table struct {
	Family string `json:"family"`
	Name   string `json:"name"`
	Handle int    `json:"handle"`
}

// Chain is one nftables chain within a table.
type Chain struct {
	Family string `json:"family"`
	Table  string `json:"table"`
	Name   string `json:"name"`
	Handle int    `json:"handle"`
	Type   string `json:"type,omitempty"`
	Hook   string `json:"hook,omitempty"`
	Prio   int    `json:"prio,omitempty"`
	Policy string `json:"policy,omitempty"`
}

// Ruleset is the structured summary of the current nftables configuration.
type Ruleset struct {
	Tables []Table
	Chains []Chain
	// RawText is the human-readable `nft list ruleset` output, useful for
	// displaying full rule details without modelling every expression type.
	RawText string
}

// nftItem mirrors one element of the "nftables" JSON array, which is a
// heterogeneous list where each object has exactly one of these keys set.
type nftItem struct {
	Table *Table `json:"table"`
	Chain *Chain `json:"chain"`
}

type nftOutput struct {
	Nftables []nftItem `json:"nftables"`
}

// ListRuleset returns the current nftables ruleset, both structured
// (tables/chains) and as raw human-readable text.
func ListRuleset() (*Ruleset, error) {
	jsonOut, err := runNft("-j", "list", "ruleset")
	if err != nil {
		return nil, fmt.Errorf("nft -j list ruleset: %w", err)
	}

	var parsed nftOutput
	if err := json.Unmarshal(jsonOut, &parsed); err != nil {
		return nil, fmt.Errorf("parsing nft json: %w", err)
	}

	rs := &Ruleset{}
	for _, item := range parsed.Nftables {
		switch {
		case item.Table != nil:
			rs.Tables = append(rs.Tables, *item.Table)
		case item.Chain != nil:
			rs.Chains = append(rs.Chains, *item.Chain)
		}
	}

	textOut, err := runNft("list", "ruleset")
	if err != nil {
		return nil, fmt.Errorf("nft list ruleset: %w", err)
	}
	rs.RawText = string(textOut)

	return rs, nil
}

func runNft(args ...string) ([]byte, error) {
	cmd := exec.Command("nft", args...)
	var stdout, stderr bytes.Buffer
	cmd.Stdout = &stdout
	cmd.Stderr = &stderr
	if err := cmd.Run(); err != nil {
		return nil, fmt.Errorf("%w: %s", err, stderr.String())
	}
	return stdout.Bytes(), nil
}
