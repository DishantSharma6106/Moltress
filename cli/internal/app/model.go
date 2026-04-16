package app

import (
	"fmt"
	"strings"
	"time"

	tea "github.com/charmbracelet/bubbletea"
	"github.com/charmbracelet/lipgloss"
)

type Quantiles struct {
	P50NS  uint64
	P99NS  uint64
	P999NS uint64
}

type ProcessMetric struct {
	PID                   uint32
	VRuntimeDriftNS       uint64
	WakeLatency           Quantiles
	VoluntarySwitchRatio  float64
	NUMAImbalanceScore    uint64
	LastCPU               uint32
}

type NetworkMetric struct {
	CgroupID   uint64
	BytesUsed  uint64
	BytesBudget uint64
	WindowNS   uint64
}

type SecurityEvent struct {
	TsNS     uint64
	UID      uint32
	Op       uint32
	Decision int32
}

type IOMetric struct {
	Opcode  uint32
	Latency Quantiles
}

type Pressure struct {
	Signal           float64
	PageFaults       uint64
	AllocFailures    uint64
	OOMKills         uint64
	HugepageFailures uint64
	KswapdWakeups    uint64
}

type DashboardFrame struct {
	TSNS            uint64
	Processes       []ProcessMetric
	Network         []NetworkMetric
	RecentSecurity  []SecurityEvent
	IO              []IOMetric
	Pressure        Pressure
}

type Source interface {
	Next() DashboardFrame
}

type DemoSource struct {
	tick uint64
}

func (d *DemoSource) Next() DashboardFrame {
	d.tick++
	return DashboardFrame{
		TSNS: uint64(time.Now().UnixNano()),
		Processes: []ProcessMetric{
			{PID: 1201, VRuntimeDriftNS: 220000 + d.tick*1000, WakeLatency: Quantiles{P50NS: 256, P99NS: 2048, P999NS: 4096}, VoluntarySwitchRatio: 0.92, NUMAImbalanceScore: 2, LastCPU: 3},
			{PID: 1217, VRuntimeDriftNS: 480000 + d.tick*2000, WakeLatency: Quantiles{P50NS: 128, P99NS: 1024, P999NS: 8192}, VoluntarySwitchRatio: 0.68, NUMAImbalanceScore: 7, LastCPU: 11},
		},
		Network: []NetworkMetric{
			{CgroupID: 4026531835, BytesUsed: 12400000, BytesBudget: 25000000, WindowNS: 1000000000},
			{CgroupID: 4026532198, BytesUsed: 6200000, BytesBudget: 12500000, WindowNS: 1000000000},
		},
		RecentSecurity: []SecurityEvent{
			{TsNS: uint64(time.Now().UnixNano()), UID: 1000, Op: 2, Decision: -1},
		},
		IO: []IOMetric{
			{Opcode: 1, Latency: Quantiles{P50NS: 512, P99NS: 8192, P999NS: 16384}},
		},
		Pressure: Pressure{Signal: 15.6, PageFaults: 920, AllocFailures: 3, OOMKills: 0, HugepageFailures: 2, KswapdWakeups: 18},
	}
}

type tickMsg struct{}

type Model struct {
	source Source
	frame  DashboardFrame
	width  int
	height int
}

func NewModel(source Source) Model {
	return Model{source: source}
}

func (m Model) Init() tea.Cmd {
	return tea.Tick(250*time.Millisecond, func(time.Time) tea.Msg { return tickMsg{} })
}

func (m Model) Update(msg tea.Msg) (tea.Model, tea.Cmd) {
	switch msg := msg.(type) {
	case tea.WindowSizeMsg:
		m.width = msg.Width
		m.height = msg.Height
		return m, nil
	case tickMsg:
		m.frame = m.source.Next()
		return m, tea.Tick(250*time.Millisecond, func(time.Time) tea.Msg { return tickMsg{} })
	case tea.KeyMsg:
		if msg.String() == "q" || msg.String() == "ctrl+c" {
			return m, tea.Quit
		}
	}

	return m, nil
}

func (m Model) View() string {
	title := lipgloss.NewStyle().Bold(true).Foreground(lipgloss.Color("204")).Render("KernelSentinel")
	section := lipgloss.NewStyle().Padding(1, 2).Border(lipgloss.RoundedBorder())

	processRows := make([]string, 0, len(m.frame.Processes))
	for _, proc := range m.frame.Processes {
		processRows = append(processRows,
			fmt.Sprintf("pid=%d drift=%dns p99=%dns ratio=%.2f numa=%d cpu=%d",
				proc.PID, proc.VRuntimeDriftNS, proc.WakeLatency.P99NS, proc.VoluntarySwitchRatio, proc.NUMAImbalanceScore, proc.LastCPU))
	}

	netRows := make([]string, 0, len(m.frame.Network))
	for _, metric := range m.frame.Network {
		netRows = append(netRows,
			fmt.Sprintf("cg=%d used=%d budget=%d", metric.CgroupID, metric.BytesUsed, metric.BytesBudget))
	}

	ioRows := make([]string, 0, len(m.frame.IO))
	for _, metric := range m.frame.IO {
		ioRows = append(ioRows,
			fmt.Sprintf("op=%d p50=%dns p99=%dns p999=%dns", metric.Opcode, metric.Latency.P50NS, metric.Latency.P99NS, metric.Latency.P999NS))
	}

	secRows := make([]string, 0, len(m.frame.RecentSecurity))
	for _, event := range m.frame.RecentSecurity {
		secRows = append(secRows,
			fmt.Sprintf("uid=%d op=%d decision=%d", event.UID, event.Op, event.Decision))
	}

	heatmap := renderHeatmap(m.frame.Processes)

	return strings.Join([]string{
		title,
		section.Render("CPU Heat\n" + heatmap),
		section.Render("Processes\n" + strings.Join(processRows, "\n")),
		section.Render("Network\n" + strings.Join(netRows, "\n")),
		section.Render("Security\n" + strings.Join(secRows, "\n")),
		section.Render("io_uring\n" + strings.Join(ioRows, "\n")),
		section.Render(fmt.Sprintf("Pressure\nsignal=%.2f faults=%d alloc_fail=%d oom=%d", m.frame.Pressure.Signal, m.frame.Pressure.PageFaults, m.frame.Pressure.AllocFailures, m.frame.Pressure.OOMKills)),
		"q: quit",
	}, "\n")
}

func renderHeatmap(processes []ProcessMetric) string {
	cells := make([]string, 0, len(processes))
	for _, proc := range processes {
		shade := lipgloss.NewStyle().Background(lipgloss.Color("63")).Foreground(lipgloss.Color("230"))
		cells = append(cells, shade.Render(fmt.Sprintf(" %02d ", proc.LastCPU)))
	}
	return strings.Join(cells, "")
}

