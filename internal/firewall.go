package agent

import (
	"bytes"
	"encoding/json"
	"fmt"
	"net/netip"
	"os/exec"
	"strings"
)

// Firewall applies the fixed set of operations.
type Firewall interface {
	Setup(allow []netip.Prefix) error
	Block(ip netip.Addr, ttlSec int) (string, error)
	Unblock(ip netip.Addr) (string, error)
	Count() int
	Backend() string
}

// Runner abstracts exec so tests and dry-run never touch the host.
type Runner func(stdin string, name string, args ...string) (string, error)

func ExecRunner(stdin string, name string, args ...string) (string, error) {
	cmd := exec.Command(name, args...)
	if stdin != "" {
		cmd.Stdin = strings.NewReader(stdin)
	}
	var out bytes.Buffer
	cmd.Stdout, cmd.Stderr = &out, &out
	err := cmd.Run()
	return strings.TrimSpace(out.String()), err
}

// NFT manages a dedicated table `inet fwctl` with timeout sets; it never touches other tables.
// In DryRun mode it only reports the nft input it would send.
type NFT struct {
	DryRun bool
	Run    Runner
}

func setFor(ip netip.Addr) string {
	if ip.Is4() {
		return "blocklist4"
	}
	return "blocklist6"
}

func SetupScript(allow []netip.Prefix) string {
	var b strings.Builder
	b.WriteString("add table inet fwctl\n")
	b.WriteString("add set inet fwctl blocklist4 { type ipv4_addr; flags timeout; }\n")
	b.WriteString("add set inet fwctl blocklist6 { type ipv6_addr; flags timeout; }\n")
	b.WriteString("add chain inet fwctl input { type filter hook input priority -10; policy accept; }\n")
	b.WriteString("flush chain inet fwctl input\n")
	for _, p := range allow {
		fam := "ip"
		if p.Addr().Is6() {
			fam = "ip6"
		}
		fmt.Fprintf(&b, "add rule inet fwctl input %s saddr %s accept\n", fam, p)
	}
	b.WriteString("add rule inet fwctl input ip saddr @blocklist4 drop\n")
	b.WriteString("add rule inet fwctl input ip6 saddr @blocklist6 drop\n")
	return b.String()
}

func (n *NFT) Backend() string { return "nftables" }

func (n *NFT) Setup(allow []netip.Prefix) error {
	if n.DryRun {
		return nil
	}
	if out, err := n.Run(SetupScript(allow), "nft", "-f", "-"); err != nil {
		return fmt.Errorf("nft setup: %s: %w", out, err)
	}
	return nil
}

func (n *NFT) Block(ip netip.Addr, ttl int) (string, error) {
	stmt := fmt.Sprintf("add element inet fwctl %s { %s timeout %ds }", setFor(ip), ip, ttl)
	if n.DryRun {
		return "DRY-RUN nft " + stmt, nil
	}
	out, err := n.Run(stmt+"\n", "nft", "-f", "-")
	return out, err
}

func (n *NFT) Unblock(ip netip.Addr) (string, error) {
	stmt := fmt.Sprintf("delete element inet fwctl %s { %s }", setFor(ip), ip)
	if n.DryRun {
		return "DRY-RUN nft " + stmt, nil
	}
	out, err := n.Run(stmt+"\n", "nft", "-f", "-")
	return out, err
}

func (n *NFT) Count() int {
	if n.DryRun {
		return 0
	}
	total := 0
	for _, s := range []string{"blocklist4", "blocklist6"} {
		if out, err := n.Run("", "nft", "-j", "list", "set", "inet", "fwctl", s); err == nil {
			total += CountSetElems(out)
		}
	}
	return total
}

// CountSetElems counts elements in `nft -j list set` output ({"nftables":[...,{"set":{...,"elem":[...]}}]}).
func CountSetElems(out string) int {
	var doc struct {
		Nftables []struct {
			Set *struct {
				Elem []json.RawMessage `json:"elem"`
			} `json:"set"`
		} `json:"nftables"`
	}
	if json.Unmarshal([]byte(out), &doc) != nil {
		return 0
	}
	n := 0
	for _, o := range doc.Nftables {
		if o.Set != nil {
			n += len(o.Set.Elem)
		}
	}
	return n
}
