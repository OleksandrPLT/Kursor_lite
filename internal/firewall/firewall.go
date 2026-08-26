// Package firewall manages real host firewall rules via ufw,
// firewalld, or raw iptables — whichever this host actually has.
// Unlike cron/vpn/dns, there's no Kursor-owned config file here (except
// iptables' own persistence file, best-effort): the backend's own live
// rule set IS the truth, queried fresh on every page load and changed
// directly through its own CLI, the same way an operator would by hand.
package firewall

import (
	"fmt"
	"os"
	"os/exec"
	"regexp"
	"strconv"
	"strings"
)

type Backend string

const (
	BackendUFW       Backend = "ufw"
	BackendFirewalld Backend = "firewalld"
	BackendIptables  Backend = "iptables"
	BackendNone      Backend = ""
)

// Detect prefers ufw (Debian/Ubuntu's default, and this project's
// "general Linux first" convention), then firewalld, and only reports
// either as usable if it's actually active — a present-but-inactive
// firewall means "not managing this host's ports right now" as far as
// the operator is concerned. Falls back to raw iptables (no on/off
// state of its own — the kernel always has *some* iptables ruleset,
// even if it's the wide-open default) when neither of the two friendly
// wrappers is running, since a minimal/hardened image often has only
// bare iptables and nothing else.
func Detect() Backend {
	if _, err := exec.LookPath("ufw"); err == nil {
		out, _ := exec.Command("ufw", "status").CombinedOutput()
		if strings.Contains(string(out), "Status: active") {
			return BackendUFW
		}
	}
	if _, err := exec.LookPath("firewall-cmd"); err == nil {
		if err := exec.Command("firewall-cmd", "--state").Run(); err == nil {
			return BackendFirewalld
		}
	}
	if _, err := exec.LookPath("iptables"); err == nil {
		return BackendIptables
	}
	return BackendNone
}

// UFWInstalled reports whether ufw is present at all (even inactive) —
// the UI uses this to offer "install" vs. "enable" distinctly.
func UFWInstalled() bool {
	_, err := exec.LookPath("ufw")
	return err == nil
}

// Rule is one allowed port.
type Rule struct {
	Port  int
	Proto string // "tcp" | "udp"
	Raw   string // the backend's own label for this rule, shown as-is for anything this package's parser doesn't fully understand
}

// ValidPort/ValidProto guard every value that reaches a shell command —
// the real injection boundary here, same role as dbmanager.ValidIdentifier.
func ValidPort(p int) bool     { return p >= 1 && p <= 65535 }
func ValidProto(p string) bool { return p == "tcp" || p == "udp" }

var ufwRuleRe = regexp.MustCompile(`^(\d+)/(tcp|udp)\s*(?:\(v6\))?\s+ALLOW`)

// iptablesRuleRe matches an ACCEPT line's protocol + destination-port
// columns from `iptables -L INPUT -n`, e.g.:
//
//	ACCEPT     tcp  --  0.0.0.0/0    0.0.0.0/0    tcp dpt:22
var iptablesRuleRe = regexp.MustCompile(`^ACCEPT\s+(tcp|udp)\s.*\bdpt:(\d+)\b`)

// ListRules returns every currently-allowed port, parsed from the
// backend's own live rule listing.
func ListRules(backend Backend) ([]Rule, error) {
	switch backend {
	case BackendUFW:
		out, err := exec.Command("ufw", "status").CombinedOutput()
		if err != nil {
			return nil, fmt.Errorf("ufw status: %s", out)
		}
		var rules []Rule
		seen := map[string]bool{}
		for _, line := range strings.Split(string(out), "\n") {
			m := ufwRuleRe.FindStringSubmatch(strings.TrimSpace(line))
			if m == nil {
				continue
			}
			key := m[1] + "/" + m[2]
			if seen[key] {
				continue // ufw lists v4/v6 as separate lines for the same rule
			}
			seen[key] = true
			port, _ := strconv.Atoi(m[1])
			rules = append(rules, Rule{Port: port, Proto: m[2], Raw: strings.TrimSpace(line)})
		}
		return rules, nil
	case BackendFirewalld:
		out, err := exec.Command("firewall-cmd", "--list-ports").CombinedOutput()
		if err != nil {
			return nil, fmt.Errorf("firewall-cmd --list-ports: %s", out)
		}
		var rules []Rule
		for _, tok := range strings.Fields(string(out)) {
			parts := strings.SplitN(tok, "/", 2)
			if len(parts) != 2 {
				continue
			}
			port, err := strconv.Atoi(parts[0])
			if err != nil {
				continue
			}
			rules = append(rules, Rule{Port: port, Proto: parts[1], Raw: tok})
		}
		return rules, nil
	case BackendIptables:
		out, err := exec.Command("iptables", "-L", "INPUT", "-n").CombinedOutput()
		if err != nil {
			return nil, fmt.Errorf("iptables -L INPUT -n: %s", out)
		}
		var rules []Rule
		seen := map[string]bool{}
		for _, line := range strings.Split(string(out), "\n") {
			m := iptablesRuleRe.FindStringSubmatch(strings.TrimSpace(line))
			if m == nil {
				continue
			}
			key := m[2] + "/" + m[1]
			if seen[key] {
				continue
			}
			seen[key] = true
			port, _ := strconv.Atoi(m[2])
			rules = append(rules, Rule{Port: port, Proto: m[1], Raw: strings.TrimSpace(line)})
		}
		return rules, nil
	default:
		return nil, fmt.Errorf("no active firewall backend detected")
	}
}

// iptablesPersist best-effort saves the current ruleset so it survives
// a reboot — there's no single standard way to do this across distros,
// so it tries the common ones in order and simply leaves the (already
// applied, already in effect) rule non-persistent if none are present,
// rather than failing the whole operation over it.
func iptablesPersist() {
	if _, err := exec.LookPath("netfilter-persistent"); err == nil {
		_, _ = exec.Command("netfilter-persistent", "save").CombinedOutput()
		return
	}
	if _, err := os.Stat("/etc/iptables"); err == nil {
		out, err := exec.Command("iptables-save").Output()
		if err == nil {
			_ = os.WriteFile("/etc/iptables/rules.v4", out, 0o644)
		}
	}
}

// OpenPort/ClosePort validate first (the only real defense — these
// values reach a real shell command) then run the backend's own real
// command, surfacing its actual output on failure.
func OpenPort(backend Backend, port int, proto string) error {
	if !ValidPort(port) || !ValidProto(proto) {
		return fmt.Errorf("invalid port/protocol")
	}
	switch backend {
	case BackendUFW:
		out, err := exec.Command("ufw", "allow", fmt.Sprintf("%d/%s", port, proto)).CombinedOutput()
		if err != nil {
			return fmt.Errorf("%s", out)
		}
		return nil
	case BackendFirewalld:
		if out, err := exec.Command("firewall-cmd", "--permanent", "--add-port="+fmt.Sprintf("%d/%s", port, proto)).CombinedOutput(); err != nil {
			return fmt.Errorf("%s", out)
		}
		out, err := exec.Command("firewall-cmd", "--reload").CombinedOutput()
		if err != nil {
			return fmt.Errorf("%s", out)
		}
		return nil
	case BackendIptables:
		out, err := exec.Command("iptables", "-A", "INPUT", "-p", proto, "--dport", strconv.Itoa(port), "-j", "ACCEPT").CombinedOutput()
		if err != nil {
			return fmt.Errorf("%s", out)
		}
		iptablesPersist()
		return nil
	default:
		return fmt.Errorf("no active firewall backend detected")
	}
}

func ClosePort(backend Backend, port int, proto string) error {
	if !ValidPort(port) || !ValidProto(proto) {
		return fmt.Errorf("invalid port/protocol")
	}
	switch backend {
	case BackendUFW:
		out, err := exec.Command("ufw", "delete", "allow", fmt.Sprintf("%d/%s", port, proto)).CombinedOutput()
		if err != nil {
			return fmt.Errorf("%s", out)
		}
		return nil
	case BackendFirewalld:
		if out, err := exec.Command("firewall-cmd", "--permanent", "--remove-port="+fmt.Sprintf("%d/%s", port, proto)).CombinedOutput(); err != nil {
			return fmt.Errorf("%s", out)
		}
		out, err := exec.Command("firewall-cmd", "--reload").CombinedOutput()
		if err != nil {
			return fmt.Errorf("%s", out)
		}
		return nil
	case BackendIptables:
		// -D deletes by exact rule specification (the same one -A added),
		// not by line number — no race with any rule added/removed by
		// something else between listing and deleting.
		out, err := exec.Command("iptables", "-D", "INPUT", "-p", proto, "--dport", strconv.Itoa(port), "-j", "ACCEPT").CombinedOutput()
		if err != nil {
			return fmt.Errorf("%s", out)
		}
		iptablesPersist()
		return nil
	default:
		return fmt.Errorf("no active firewall backend detected")
	}
}

// EnableUFW allows every port in mustAllowFirst (deduplicated, SSH
// implicitly always included) before ever turning ufw on — the warning
// this page shows next to the button used to be just words; now the
// port that warning is about (SSH) is guaranteed allowed before enable
// ever runs, not left to the operator to remember. `--force` skips
// ufw's own interactive "this may disrupt SSH" prompt, which would
// otherwise hang forever with no TTY attached.
func EnableUFW(mustAllowFirst []int) error {
	ports := map[int]bool{22: true}
	for _, p := range mustAllowFirst {
		if ValidPort(p) {
			ports[p] = true
		}
	}
	for p := range ports {
		if out, err := exec.Command("ufw", "allow", fmt.Sprintf("%d/tcp", p)).CombinedOutput(); err != nil {
			return fmt.Errorf("ufw allow %d/tcp: %s", p, out)
		}
	}
	out, err := exec.Command("ufw", "--force", "enable").CombinedOutput()
	if err != nil {
		return fmt.Errorf("%s", out)
	}
	return nil
}

// CommonPort is one entry in the standard-ports quick-list — the "add
// all possible standard ports" convenience: an operator picks a
// well-known service instead of having to know/type its port number.
type CommonPort struct {
	Name  string
	Port  int
	Proto string
	Group string
}

// CommonPorts covers every standard service a general-purpose server
// panel commonly needs — grouped for the UI. Picking one just opens
// that port; it never installs or configures the service itself (that
// stays each module's own job — Sites/VPN/DNS/Mail/Software elsewhere
// in Kursor).
var CommonPorts = []CommonPort{
	// Remote access
	{"SSH", 22, "tcp", "Remote access"},
	{"Telnet", 23, "tcp", "Remote access"},
	{"RDP", 3389, "tcp", "Remote access"},
	{"VNC", 5900, "tcp", "Remote access"},

	// Web
	{"HTTP", 80, "tcp", "Web"},
	{"HTTPS", 443, "tcp", "Web"},
	{"HTTP (alt)", 8080, "tcp", "Web"},
	{"HTTPS (alt)", 8443, "tcp", "Web"},

	// File transfer
	{"FTP", 21, "tcp", "File transfer"},
	{"FTP data", 20, "tcp", "File transfer"},
	{"SFTP/SCP", 22, "tcp", "File transfer"},
	{"TFTP", 69, "udp", "File transfer"},

	// Mail
	{"SMTP", 25, "tcp", "Mail"},
	{"SMTPS", 465, "tcp", "Mail"},
	{"SMTP Submission", 587, "tcp", "Mail"},
	{"POP3", 110, "tcp", "Mail"},
	{"POP3S", 995, "tcp", "Mail"},
	{"IMAP", 143, "tcp", "Mail"},
	{"IMAPS", 993, "tcp", "Mail"},

	// DNS
	{"DNS", 53, "tcp", "DNS"},
	{"DNS", 53, "udp", "DNS"},

	// Databases
	{"MySQL / MariaDB", 3306, "tcp", "Databases"},
	{"PostgreSQL", 5432, "tcp", "Databases"},
	{"MongoDB", 27017, "tcp", "Databases"},
	{"Redis", 6379, "tcp", "Databases"},
	{"Memcached", 11211, "tcp", "Databases"},
	{"MSSQL", 1433, "tcp", "Databases"},
	{"Elasticsearch", 9200, "tcp", "Databases"},
	{"CouchDB", 5984, "tcp", "Databases"},

	// VPN
	{"WireGuard", 51820, "udp", "VPN"},
	{"OpenVPN", 1194, "udp", "VPN"},
	{"IPsec IKE", 500, "udp", "VPN"},
	{"IPsec NAT-T", 4500, "udp", "VPN"},
	{"PPTP", 1723, "tcp", "VPN"},

	// Monitoring & dev tools
	{"Prometheus", 9090, "tcp", "Monitoring & dev tools"},
	{"Grafana", 3000, "tcp", "Monitoring & dev tools"},
	{"InfluxDB", 8086, "tcp", "Monitoring & dev tools"},
	{"Docker API", 2375, "tcp", "Monitoring & dev tools"},
	{"Docker API (TLS)", 2376, "tcp", "Monitoring & dev tools"},
	{"Node.js (common)", 3000, "tcp", "Monitoring & dev tools"},

	// Messaging & queues
	{"RabbitMQ", 5672, "tcp", "Messaging & queues"},
	{"RabbitMQ mgmt", 15672, "tcp", "Messaging & queues"},
	{"Kafka", 9092, "tcp", "Messaging & queues"},
	{"MQTT", 1883, "tcp", "Messaging & queues"},

	// Network services
	{"NTP", 123, "udp", "Network services"},
	{"SNMP", 161, "udp", "Network services"},
	{"Syslog", 514, "udp", "Network services"},
	{"LDAP", 389, "tcp", "Network services"},
	{"LDAPS", 636, "tcp", "Network services"},
}
