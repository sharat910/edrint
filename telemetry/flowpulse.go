package telemetry

import (
	"fmt"
	"time"

	"github.com/rs/zerolog/log"
	"github.com/sharat910/edrint/packets"
	"github.com/spf13/viper"
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

func NewFlowPulse() *FlowPulse {
	var fp FlowPulse
	interval := viper.GetInt(fmt.Sprintf("telemetry.%s.interval_ms", fp.Name()))
	if interval == 0 {
		log.Warn().Msg("tcp_retransmit_simple unable to read interval. Setting default: 1sec")
		interval = 1000
	}
	log.Debug().Str("telemetry", fp.Name()).Int("interval", interval).Msg("config")
	fp.intervalMS = interval
	return &fp
}

func (f *FlowPulse) Name() string {
	return "flowpulse"
}

func (f *FlowPulse) OnFlowPacket(p packets.Packet) {
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
	f.Publish("telemetry.flowpulse", DataFlowPulse{
		Header:        f.header,
		IntervalMS:    f.intervalMS,
		FirstPacketTS: f.firstPacketTS,
		LastPacketTS:  f.lastPacketTS,
		DownBytes:     f.downBytes,
		UpBytes:       f.upBytes,
		DownPackets:   f.downPackets,
		UpPackets:     f.upPackets,
	})
}

func (f *FlowPulse) Update(p packets.Packet, idx int) {
	if p.IsOutbound {
		f.upPackets[idx]++
		f.upBytes[idx] += p.TotalLen
	} else {
		f.downPackets[idx]++
		f.downBytes[idx] += p.TotalLen
	}
}

type DataFlowPulse struct {
	Header        packets.FiveTuple
	IntervalMS    int
	FirstPacketTS time.Time
	LastPacketTS  time.Time
	DownBytes     []uint
	UpBytes       []uint
	DownPackets   []uint
	UpPackets     []uint
}
