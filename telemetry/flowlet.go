package telemetry

import (
	"fmt"
	"time"

	"github.com/rs/zerolog/log"
	"github.com/sharat910/edrint/common"
	"github.com/sharat910/edrint/events"
)

type Flowlet struct {
	FirstPacketTS time.Time `json:"first_packet_ts"`
	LastPacketTS  time.Time `json:"-"`
	Bytes         int       `json:"bytes"`
	Packets       int       `json:"packets"`
	DurationUS    int       `json:"duration_us"`
	GapPrevMS     int       `json:"gap_ms"`
}

type FlowletTracker struct {
	BaseFlowTelemetry
	gap         time.Duration
	FirstDownTS time.Time
	LastDownTS  time.Time
	Flowlets    []Flowlet
}

func (ft *FlowletTracker) Pubs() []events.Topic {
	return []events.Topic{events.TELEMETRY_FLOWLET}
}

func NewFlowletTracker(gap time.Duration) TeleGen {
	return func() Telemetry {
		return &FlowletTracker{gap: gap}
	}
}

func (ft *FlowletTracker) Name() string {
	return "flowlet_tracker"
}

func (ft *FlowletTracker) OnFlowPacket(p common.Packet) {
	if p.IsOutbound {
		return
	}

	if ft.FirstDownTS.IsZero() {
		ft.FirstDownTS = p.Timestamp
		ft.LastDownTS = p.Timestamp
		ft.Flowlets = append(ft.Flowlets, Flowlet{})
		ft.Flowlets[0].FirstPacketTS = p.Timestamp
	}

	if p.Timestamp.Sub(ft.LastDownTS) > ft.gap {
		lastFlowlet := ft.Flowlets[len(ft.Flowlets)-1]
		ft.Flowlets[len(ft.Flowlets)-1].DurationUS = int(lastFlowlet.LastPacketTS.Sub(lastFlowlet.FirstPacketTS) / time.Microsecond)
		log.Debug().Str("header", ft.header.String()).Str("z_flowlet", fmt.Sprintf("%+v", ft.Flowlets[len(ft.Flowlets)-1])).Send()
		ft.Flowlets = append(ft.Flowlets, Flowlet{FirstPacketTS: p.Timestamp, GapPrevMS: int(p.Timestamp.Sub(ft.LastDownTS) / time.Millisecond)})
	}
	lastIdx := len(ft.Flowlets) - 1
	ft.Flowlets[lastIdx].LastPacketTS = p.Timestamp
	ft.Flowlets[lastIdx].Bytes += len(p.Payload)
	ft.Flowlets[lastIdx].Packets++
	ft.LastDownTS = p.Timestamp
}

type FlowletExport struct {
	Header      common.FiveTuple
	FirstDownTS time.Time
	Duration    time.Duration
	Flowlets    []Flowlet
}

func (ft *FlowletTracker) Teardown() {
	if len(ft.Flowlets) > 0 {
		lastFlowlet := ft.Flowlets[len(ft.Flowlets)-1]
		ft.Flowlets[len(ft.Flowlets)-1].DurationUS = int(lastFlowlet.LastPacketTS.Sub(lastFlowlet.FirstPacketTS) / time.Microsecond)
		//ft.LogSummary()
	}

	ft.Publish(events.TELEMETRY_FLOWLET, FlowletExport{
		ft.header,
		ft.FirstDownTS,
		ft.LastDownTS.Sub(ft.FirstDownTS),
		ft.Flowlets})
}

func (ft *FlowletTracker) LogSummary() {
	totalVol := 0
	totalTime := 0
	for _, fl := range ft.Flowlets {
		if fl.Packets < 5 {
			continue
		}
		totalVol += fl.Bytes
		totalTime += fl.DurationUS
	}
	if totalVol > 0 {
		log.Info().Str("header", ft.GetHeader().String()).Int("ns/b", 1e3*totalTime/totalVol).Msg("flowlet_summary")
	}
}
