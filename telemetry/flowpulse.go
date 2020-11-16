package telemetry

import (
	"time"

	"github.com/sharat910/edrint/common"
	"github.com/sharat910/edrint/events"

	"github.com/rs/zerolog/log"
)

type FlowPulse struct {
	BaseFlowTelemetry
	intervalMS    int
	firstPacketTS time.Time
	lastPacketTS  time.Time
	downBytes     []uint
	upBytes       []uint
	downPackets   []uint
	upPackets     []uint

	firstPacketSeen bool
	curIdx          int
}

func (f *FlowPulse) Pubs() []events.Topic {
	return []events.Topic{events.TELEMETRY_FLOWPULSE}
}

func NewFlowPulse(intervalMS int) TeleGen {
	if intervalMS == 0 {
		log.Warn().Msg("tcp_retransmit_simple unable to read interval. Setting default: 1sec")
		intervalMS = 1000
	}
	return func() Telemetry {
		var fp FlowPulse
		fp.intervalMS = intervalMS
		log.Debug().Str("telemetry", fp.Name()).Int("interval_ms", intervalMS).Msg("config")
		return &fp
	}
}

func (f *FlowPulse) Name() string {
	return "flowpulse"
}

func (f *FlowPulse) OnFlowPacket(p common.Packet) {
	if !f.firstPacketSeen {
		f.firstPacketTS = p.Timestamp
		f.firstPacketSeen = true
	}

	idx, err := GetIndex(f.firstPacketTS, p.Timestamp, f.intervalMS)
	if err != nil {
		log.Warn().Err(err).Str("telemetry", f.Name()).Msg("get_index throwing err")
		return
	}

	f.ExtendUntil(idx)
	f.Update(p, idx)
	f.lastPacketTS = p.Timestamp
}

func (f *FlowPulse) ExtendUntil(idx int) {
	for i := len(f.downBytes); i <= idx; i++ {
		f.downBytes = append(f.downBytes, 0)
		f.upBytes = append(f.upBytes, 0)
		f.downPackets = append(f.downPackets, 0)
		f.upPackets = append(f.upPackets, 0)
	}
}

func (f *FlowPulse) Teardown() {
	log.Debug().Str("telemetry", f.Name()).Msg("teardown")
	f.Publish(events.TELEMETRY_FLOWPULSE, struct {
		Header        common.FiveTuple
		IntervalMS    int
		FirstPacketTS time.Time
		LastPacketTS  time.Time
		DownBytes     []uint
		UpBytes       []uint
		DownPackets   []uint
		UpPackets     []uint
	}{
		f.header,
		f.intervalMS,
		f.firstPacketTS,
		f.lastPacketTS,
		f.downBytes,
		f.upBytes,
		f.downPackets,
		f.upPackets,
	})
}

func (f *FlowPulse) Update(p common.Packet, idx int) {
	if p.IsOutbound {
		f.upPackets[idx]++
		f.upBytes[idx] += p.TotalLen
	} else {
		f.downPackets[idx]++
		f.downBytes[idx] += p.TotalLen
	}
}
