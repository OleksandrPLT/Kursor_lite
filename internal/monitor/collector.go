// Package monitor polls live system resource usage (CPU, memory, disk,
// network) with gopsutil and fans it out to Server-Sent Events
// subscribers. No long-term persistence — the MVP only needs the latest
// reading plus whatever a connected browser tab wants to keep client-side.
package monitor

import (
	"context"
	"sync"
	"time"

	"github.com/shirou/gopsutil/v4/cpu"
	"github.com/shirou/gopsutil/v4/disk"
	"github.com/shirou/gopsutil/v4/mem"
	"github.com/shirou/gopsutil/v4/net"
)

// Sample is one point-in-time reading, sent to the browser as JSON.
type Sample struct {
	Time time.Time `json:"time"`

	CPUPercent float64 `json:"cpuPercent"`
	CPUCores   int     `json:"cpuCores"`

	MemPercent float64 `json:"memPercent"`
	MemUsedGB  float64 `json:"memUsedGB"`
	MemTotalGB float64 `json:"memTotalGB"`

	DiskPercent  float64 `json:"diskPercent"`
	DiskUsedGB   float64 `json:"diskUsedGB"`
	DiskTotalGB  float64 `json:"diskTotalGB"`

	NetDownKBs float64 `json:"netDownKBs"`
	NetUpKBs   float64 `json:"netUpKBs"`
	NetIface   string  `json:"netIface"`
}

// Collector polls system stats on an interval and fans them out to any
// number of subscribers (one per open SSE connection).
type Collector struct {
	interval time.Duration
	diskPath string

	mu     sync.Mutex
	latest Sample
	has    bool
	subs   map[chan Sample]struct{}

	prevNetBytesRecv uint64
	prevNetBytesSent uint64
	prevNetTime      time.Time
}

// NewCollector builds a collector that samples every interval and reports
// disk usage for diskPath (e.g. "/").
func NewCollector(interval time.Duration, diskPath string) *Collector {
	return &Collector{
		interval: interval,
		diskPath: diskPath,
		subs:     make(map[chan Sample]struct{}),
	}
}

// Run polls until ctx is cancelled. Intended to be started in its own
// goroutine from main.
func (c *Collector) Run(ctx context.Context) {
	// Prime cpu.Percent's internal baseline so the first real reading
	// reflects a real interval rather than "since process start".
	_, _ = cpu.Percent(0, false)

	ticker := time.NewTicker(c.interval)
	defer ticker.Stop()

	for {
		select {
		case <-ctx.Done():
			return
		case <-ticker.C:
			s := c.collect()
			c.publish(s)
		}
	}
}

func (c *Collector) collect() Sample {
	s := Sample{Time: time.Now(), NetIface: "all interfaces"}

	if pct, err := cpu.Percent(0, false); err == nil && len(pct) > 0 {
		s.CPUPercent = pct[0]
	}
	if n, err := cpu.Counts(true); err == nil {
		s.CPUCores = n
	}

	if vm, err := mem.VirtualMemory(); err == nil {
		s.MemPercent = vm.UsedPercent
		s.MemUsedGB = bytesToGB(vm.Used)
		s.MemTotalGB = bytesToGB(vm.Total)
	}

	if du, err := disk.Usage(c.diskPath); err == nil {
		s.DiskPercent = du.UsedPercent
		s.DiskUsedGB = bytesToGB(du.Used)
		s.DiskTotalGB = bytesToGB(du.Total)
	}

	if counters, err := net.IOCounters(false); err == nil && len(counters) > 0 {
		total := counters[0]
		now := time.Now()
		if !c.prevNetTime.IsZero() {
			elapsed := now.Sub(c.prevNetTime).Seconds()
			if elapsed > 0 {
				s.NetDownKBs = deltaKBs(c.prevNetBytesRecv, total.BytesRecv, elapsed)
				s.NetUpKBs = deltaKBs(c.prevNetBytesSent, total.BytesSent, elapsed)
			}
		}
		c.prevNetBytesRecv = total.BytesRecv
		c.prevNetBytesSent = total.BytesSent
		c.prevNetTime = now
	}

	return s
}

func bytesToGB(b uint64) float64 {
	return float64(b) / (1024 * 1024 * 1024)
}

func deltaKBs(prev, cur uint64, elapsedSeconds float64) float64 {
	if cur < prev {
		// counters reset (interface flap, overflow) — report 0 rather
		// than a nonsensical negative spike.
		return 0
	}
	return float64(cur-prev) / 1024 / elapsedSeconds
}

func (c *Collector) publish(s Sample) {
	c.mu.Lock()
	c.latest = s
	c.has = true
	subs := make([]chan Sample, 0, len(c.subs))
	for ch := range c.subs {
		subs = append(subs, ch)
	}
	c.mu.Unlock()

	for _, ch := range subs {
		select {
		case ch <- s:
		default:
			// slow subscriber — drop the sample rather than block the
			// collector loop for everyone else.
		}
	}
}

// Latest returns the most recent sample, if any has been collected yet.
func (c *Collector) Latest() (Sample, bool) {
	c.mu.Lock()
	defer c.mu.Unlock()
	return c.latest, c.has
}

// Subscribe registers ch to receive future samples. Callers must call
// Unsubscribe when done (typically via defer).
func (c *Collector) Subscribe(ch chan Sample) {
	c.mu.Lock()
	defer c.mu.Unlock()
	c.subs[ch] = struct{}{}
}

// Unsubscribe removes ch from the subscriber list.
func (c *Collector) Unsubscribe(ch chan Sample) {
	c.mu.Lock()
	defer c.mu.Unlock()
	delete(c.subs, ch)
}
