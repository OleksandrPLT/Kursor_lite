package server

import (
	"fmt"
	"net"
	"os"
	"time"

	"github.com/shirou/gopsutil/v4/cpu"
	"github.com/shirou/gopsutil/v4/host"
)

// hostSnapshot is real (not sample) data about the machine Kursor is
// running on, used for the sidebar server card and dashboard header.
type hostSnapshot struct {
	Hostname string
	IP       string
	OS       string
	Uptime   string
	CPUCores int
}

func getHostSnapshot() hostSnapshot {
	snap := hostSnapshot{Hostname: "unknown", IP: "unknown", OS: "unknown", Uptime: "unknown"}

	if hn, err := os.Hostname(); err == nil {
		snap.Hostname = hn
	}
	if ip := localIPv4(); ip != "" {
		snap.IP = ip
	}
	if info, err := host.Info(); err == nil {
		snap.OS = fmt.Sprintf("%s %s", info.Platform, info.PlatformVersion)
		snap.Uptime = formatUptime(time.Duration(info.Uptime) * time.Second)
	}
	if n, err := cpu.Counts(true); err == nil {
		snap.CPUCores = n
	}
	return snap
}

// localIPv4 returns the first non-loopback IPv4 address of any active
// network interface, best-effort (mirrors what install.sh's `hostname -I`
// does on a real Linux server, per the build plan).
func localIPv4() string {
	addrs, err := net.InterfaceAddrs()
	if err != nil {
		return ""
	}
	for _, a := range addrs {
		ipNet, ok := a.(*net.IPNet)
		if !ok || ipNet.IP.IsLoopback() {
			continue
		}
		if v4 := ipNet.IP.To4(); v4 != nil {
			return v4.String()
		}
	}
	return ""
}

func formatUptime(d time.Duration) string {
	days := int(d.Hours()) / 24
	hours := int(d.Hours()) % 24
	minutes := int(d.Minutes()) % 60
	if days > 0 {
		return fmt.Sprintf("%dd %dh %dm", days, hours, minutes)
	}
	if hours > 0 {
		return fmt.Sprintf("%dh %dm", hours, minutes)
	}
	return fmt.Sprintf("%dm", minutes)
}
