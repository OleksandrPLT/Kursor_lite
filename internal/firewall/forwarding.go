package firewall

import (
	"fmt"
	"net"
	"os"
	"os/exec"
	"regexp"
	"strconv"
	"strings"
)

// Forward is one port-forwarding (DNAT) rule: connections to
// external_port on this host get forwarded to internal_ip:internal_port
// — e.g. exposing a Docker container or an internal VM's service
// through this box's own public IP.
type Forward struct {
	ExternalPort  int
	ExternalProto string
	InternalIP    string
	InternalPort  int
}

// ValidInternalIP is deliberately just IPv4/IPv6 syntax validation
// (net.ParseIP) — the same injection boundary role DNS's net.ParseIP
// check plays, since this value reaches iptables/firewall-cmd command
// lines and a ufw config file line.
func ValidInternalIP(ip string) bool { return net.ParseIP(ip) != nil }

// EnableIPForwarding turns on kernel IP forwarding (net.ipv4.ip_forward)
// — required for any DNAT-based port forward to actually work,
// regardless of backend — and persists it so it survives a reboot.
func EnableIPForwarding() error {
	if out, err := exec.Command("sysctl", "-w", "net.ipv4.ip_forward=1").CombinedOutput(); err != nil {
		return fmt.Errorf("sysctl -w net.ipv4.ip_forward=1: %s", out)
	}
	_ = os.MkdirAll("/etc/sysctl.d", 0o755)
	_ = os.WriteFile("/etc/sysctl.d/99-kursor-forwarding.conf", []byte("net.ipv4.ip_forward = 1\n"), 0o644)
	return nil
}

// AddForward applies one DNAT rule via whichever backend is active.
func AddForward(backend Backend, f Forward) error {
	if !ValidPort(f.ExternalPort) || !ValidPort(f.InternalPort) || !ValidProto(f.ExternalProto) || !ValidInternalIP(f.InternalIP) {
		return fmt.Errorf("invalid port forward parameters")
	}
	switch backend {
	case BackendFirewalld:
		spec := fmt.Sprintf("port=%d:proto=%s:toport=%d:toaddr=%s", f.ExternalPort, f.ExternalProto, f.InternalPort, f.InternalIP)
		if out, err := exec.Command("firewall-cmd", "--permanent", "--add-forward-port="+spec).CombinedOutput(); err != nil {
			return fmt.Errorf("%s", out)
		}
		if out, err := exec.Command("firewall-cmd", "--permanent", "--add-masquerade").CombinedOutput(); err != nil {
			return fmt.Errorf("%s", out)
		}
		out, err := exec.Command("firewall-cmd", "--reload").CombinedOutput()
		if err != nil {
			return fmt.Errorf("%s", out)
		}
		return nil
	case BackendIptables:
		if err := EnableIPForwarding(); err != nil {
			return err
		}
		extPort, intPort := strconv.Itoa(f.ExternalPort), strconv.Itoa(f.InternalPort)
		dest := f.InternalIP + ":" + intPort
		if out, err := exec.Command("iptables", "-t", "nat", "-A", "PREROUTING", "-p", f.ExternalProto, "--dport", extPort, "-j", "DNAT", "--to-destination", dest).CombinedOutput(); err != nil {
			return fmt.Errorf("%s", out)
		}
		if out, err := exec.Command("iptables", "-t", "nat", "-A", "POSTROUTING", "-p", f.ExternalProto, "-d", f.InternalIP, "--dport", intPort, "-j", "MASQUERADE").CombinedOutput(); err != nil {
			return fmt.Errorf("%s", out)
		}
		if out, err := exec.Command("iptables", "-A", "FORWARD", "-p", f.ExternalProto, "-d", f.InternalIP, "--dport", intPort, "-j", "ACCEPT").CombinedOutput(); err != nil {
			return fmt.Errorf("%s", out)
		}
		iptablesPersist()
		return nil
	case BackendUFW:
		if err := EnableIPForwarding(); err != nil {
			return err
		}
		if err := setUFWForwardPolicy(); err != nil {
			return err
		}
		forwards, err := readUFWForwards()
		if err != nil {
			return err
		}
		forwards = append(forwards, f)
		if err := writeUFWForwards(forwards); err != nil {
			return err
		}
		out, err := exec.Command("ufw", "reload").CombinedOutput()
		if err != nil {
			return fmt.Errorf("ufw reload: %s", out)
		}
		return nil
	default:
		return fmt.Errorf("no active firewall backend detected")
	}
}

// RemoveForward undoes AddForward's rule for the same backend.
func RemoveForward(backend Backend, f Forward) error {
	switch backend {
	case BackendFirewalld:
		spec := fmt.Sprintf("port=%d:proto=%s:toport=%d:toaddr=%s", f.ExternalPort, f.ExternalProto, f.InternalPort, f.InternalIP)
		out, err := exec.Command("firewall-cmd", "--permanent", "--remove-forward-port="+spec).CombinedOutput()
		if err != nil {
			return fmt.Errorf("%s", out)
		}
		_, _ = exec.Command("firewall-cmd", "--reload").CombinedOutput()
		return nil
	case BackendIptables:
		extPort, intPort := strconv.Itoa(f.ExternalPort), strconv.Itoa(f.InternalPort)
		dest := f.InternalIP + ":" + intPort
		_, _ = exec.Command("iptables", "-t", "nat", "-D", "PREROUTING", "-p", f.ExternalProto, "--dport", extPort, "-j", "DNAT", "--to-destination", dest).CombinedOutput()
		_, _ = exec.Command("iptables", "-t", "nat", "-D", "POSTROUTING", "-p", f.ExternalProto, "-d", f.InternalIP, "--dport", intPort, "-j", "MASQUERADE").CombinedOutput()
		_, _ = exec.Command("iptables", "-D", "FORWARD", "-p", f.ExternalProto, "-d", f.InternalIP, "--dport", intPort, "-j", "ACCEPT").CombinedOutput()
		iptablesPersist()
		return nil
	case BackendUFW:
		forwards, err := readUFWForwards()
		if err != nil {
			return err
		}
		kept := forwards[:0]
		for _, existing := range forwards {
			if existing != f {
				kept = append(kept, existing)
			}
		}
		if err := writeUFWForwards(kept); err != nil {
			return err
		}
		out, err := exec.Command("ufw", "reload").CombinedOutput()
		if err != nil {
			return fmt.Errorf("ufw reload: %s", out)
		}
		return nil
	default:
		return fmt.Errorf("no active firewall backend detected")
	}
}

// --- ufw's port forwarding: a *nat table block spliced into
// /etc/ufw/before.rules, since ufw itself has no forward-port command
// (unlike firewalld). Regenerated in full from the current list every
// time, marker-delimited, same splice discipline as internal/cron's
// crontab block — never touches anything else in the file. ---

const ufwBeforeRulesPath = "/etc/ufw/before.rules"
const ufwDefaultsPath = "/etc/default/ufw"

var (
	ufwBeginMarker   = "# >>> kursor port forwarding — do not edit below by hand >>>"
	ufwEndMarker     = "# <<< kursor port forwarding <<<"
	ufwForwardLineRe = regexp.MustCompile(`^-A PREROUTING -p (tcp|udp) --dport (\d+) -j DNAT --to-destination ([0-9.]+):(\d+)$`)
)

func renderUFWNatBlock(forwards []Forward) string {
	if len(forwards) == 0 {
		return ""
	}
	var b strings.Builder
	b.WriteString(ufwBeginMarker + "\n")
	b.WriteString("*nat\n:PREROUTING ACCEPT [0:0]\n:POSTROUTING ACCEPT [0:0]\n")
	for _, f := range forwards {
		fmt.Fprintf(&b, "-A PREROUTING -p %s --dport %d -j DNAT --to-destination %s:%d\n", f.ExternalProto, f.ExternalPort, f.InternalIP, f.InternalPort)
		fmt.Fprintf(&b, "-A POSTROUTING -p %s -d %s --dport %d -j MASQUERADE\n", f.ExternalProto, f.InternalIP, f.InternalPort)
	}
	b.WriteString("COMMIT\n")
	b.WriteString(ufwEndMarker + "\n")
	return b.String()
}

// parseUFWNatBlock is renderUFWNatBlock's inverse — reads back whatever
// forwards are currently spliced into before.rules, so AddForward/
// RemoveForward only ever need to append/filter a Go slice, never
// hand-edit the file's text directly.
func parseUFWNatBlock(content string) []Forward {
	var out []Forward
	for _, line := range strings.Split(content, "\n") {
		m := ufwForwardLineRe.FindStringSubmatch(strings.TrimSpace(line))
		if m == nil {
			continue
		}
		port, _ := strconv.Atoi(m[2])
		intPort, _ := strconv.Atoi(m[4])
		out = append(out, Forward{ExternalProto: m[1], ExternalPort: port, InternalIP: m[3], InternalPort: intPort})
	}
	return out
}

func spliceBlock(existing, beginMarker, endMarker, newBlock string) string {
	begin := strings.Index(existing, beginMarker)
	end := strings.Index(existing, endMarker)
	var before, after string
	if begin >= 0 && end >= 0 && end > begin {
		before = strings.TrimRight(existing[:begin], "\n")
		after = strings.TrimLeft(existing[end+len(endMarker):], "\n")
	} else {
		before = strings.TrimRight(existing, "\n")
	}
	parts := make([]string, 0, 3)
	if before != "" {
		parts = append(parts, before)
	}
	if newBlock != "" {
		parts = append(parts, strings.TrimRight(newBlock, "\n"))
	}
	if after != "" {
		parts = append(parts, after)
	}
	return strings.Join(parts, "\n") + "\n"
}

func readUFWForwards() ([]Forward, error) {
	content, err := os.ReadFile(ufwBeforeRulesPath)
	if err != nil {
		if os.IsNotExist(err) {
			return nil, nil
		}
		return nil, err
	}
	return parseUFWNatBlock(string(content)), nil
}

func writeUFWForwards(forwards []Forward) error {
	existing, err := os.ReadFile(ufwBeforeRulesPath)
	if err != nil {
		return fmt.Errorf("read %s: %w", ufwBeforeRulesPath, err)
	}
	updated := spliceBlock(string(existing), ufwBeginMarker, ufwEndMarker, renderUFWNatBlock(forwards))
	return os.WriteFile(ufwBeforeRulesPath, []byte(updated), 0o640)
}

// setUFWForwardPolicy flips DEFAULT_FORWARD_POLICY to ACCEPT in
// /etc/default/ufw — ufw's own default is DROP, which would silently
// discard every forwarded packet in the FORWARD chain regardless of the
// nat table rules above.
func setUFWForwardPolicy() error {
	content, err := os.ReadFile(ufwDefaultsPath)
	if err != nil {
		return fmt.Errorf("read %s: %w", ufwDefaultsPath, err)
	}
	policyRe := regexp.MustCompile(`(?m)^DEFAULT_FORWARD_POLICY=.*$`)
	updated := policyRe.ReplaceAllString(string(content), `DEFAULT_FORWARD_POLICY="ACCEPT"`)
	if updated == string(content) && !strings.Contains(updated, "DEFAULT_FORWARD_POLICY") {
		updated = strings.TrimRight(updated, "\n") + "\nDEFAULT_FORWARD_POLICY=\"ACCEPT\"\n"
	}
	return os.WriteFile(ufwDefaultsPath, []byte(updated), 0o644)
}
