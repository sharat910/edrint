package telemetry

import (
	"time"

	"github.com/sharat910/edrint/common"
	"github.com/sharat910/edrint/events"
)

type FlowSummary struct {
	BaseFlowTelemetry
	FirstPacket      time.Time
	LastPacket       time.Time
	UpTotalBytes     int
	UpPayloadBytes   int
	DownTotalBytes   int
	DownPayloadBytes int
	UpPackets        int
	DownPackets      int
}

func NewFlowSummary() TeleGen {
	return func() Telemetry {
		return &FlowSummary{}
	}
}

func (f *FlowSummary) Name() string {
	return "flow_summary"
}

func (f *FlowSummary) OnFlowPacket(p common.Packet) {
	if f.FirstPacket.IsZero() {
		f.FirstPacket = p.Timestamp
	}
	f.LastPacket = p.Timestamp
	if p.IsOutbound {
		f.UpTotalBytes += int(p.TotalLen)
		f.UpPayloadBytes += len(p.Payload)
		f.UpPackets++
	} else {
		f.DownTotalBytes += int(p.TotalLen)
		f.DownPayloadBytes += len(p.Payload)
		f.DownPackets++
	}
}

func (f *FlowSummary) Pubs() []events.Topic {
	return []events.Topic{events.TELEMETRY_FLOWSUMMARY}
}

func (f *FlowSummary) Teardown() {
	f.Publish(events.TELEMETRY_FLOWSUMMARY, struct {
		Header           common.FiveTuple
		FirstPacket      time.Time
		LastPacket       time.Time
		UpTotalBytes     int
		UpPayloadBytes   int
		DownTotalBytes   int
		DownPayloadBytes int
		UpPackets        int
		DownPackets      int
	}{
		f.header,
		f.FirstPacket,
		f.LastPacket,
		f.UpTotalBytes,
		f.UpPayloadBytes,
		f.DownTotalBytes,
		f.DownPayloadBytes,
		f.UpPackets,
		f.DownPackets,
	})
}
