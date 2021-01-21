package telemetry

import (
	"time"

	"github.com/sharat910/edrint/common"
	"github.com/sharat910/edrint/events"

	"github.com/rs/zerolog/log"
)

type FlowPrint struct {
	BaseFlowTelemetry
	intervalMS    int
	firstPacketTS time.Time
	lastPacketTS  time.Time
	downBytes     []uint
	upBytes       []uint
	downPackets   []uint
	upPackets     []uint

	downZeros []uint
	upZeros   []uint

	downMids     []uint
	downMidBytes []uint
	upMids       []uint
	upMidBytes   []uint

	downHighs     []uint
	downHighBytes []uint
	upHighs       []uint
	upHighBytes   []uint

	firstPacketSeen bool
	curIdx          int
}

func (f *FlowPrint) Pubs() []events.Topic {
	return []events.Topic{events.TELEMETRY_FLOWPRINT}
}

func NewFlowPrint(intervalMS int) TeleGen {
	if intervalMS == 0 {
		log.Warn().Msg("flowprint unable to read interval. Setting default: 1sec")
		intervalMS = 1000
	}
	return func() Telemetry {
		var fp FlowPrint
		fp.intervalMS = intervalMS
		log.Debug().Str("telemetry", fp.Name()).Int("interval_ms", intervalMS).Msg("tele init")
		return &fp
	}
}

func (f *FlowPrint) Name() string {
	return "flowprint"
}

func (f *FlowPrint) OnFlowPacket(p common.Packet) {
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

func (f *FlowPrint) ExtendUntil(idx int) {
	for i := len(f.downBytes); i <= idx; i++ {
		f.downBytes = append(f.downBytes, 0)
		f.upBytes = append(f.upBytes, 0)
		f.downPackets = append(f.downPackets, 0)
		f.upPackets = append(f.upPackets, 0)

		f.downZeros = append(f.downZeros, 0)
		f.upZeros = append(f.upZeros, 0)

		f.downMids = append(f.downMids, 0)
		f.downMidBytes = append(f.downMidBytes, 0)
		f.upMids = append(f.upMids, 0)
		f.upMidBytes = append(f.upMidBytes, 0)

		f.downHighs = append(f.downHighs, 0)
		f.downHighBytes = append(f.downHighBytes, 0)
		f.upHighs = append(f.upHighs, 0)
		f.upHighBytes = append(f.upHighBytes, 0)
	}
}

func (f *FlowPrint) Teardown() {
	log.Debug().Str("telemetry", f.Name()).Msg("teardown")
	f.Publish(events.TELEMETRY_FLOWPRINT, struct {
		Header        common.FiveTuple
		IntervalMS    int
		FirstPacketTS time.Time
		LastPacketTS  time.Time
		DownBytes     []uint
		UpBytes       []uint
		DownPackets   []uint
		UpPackets     []uint
		DownZeros     []uint
		UpZeros       []uint
		DownMids      []uint
		DownMidBytes  []uint
		UpMids        []uint
		UpMidBytes    []uint
		DownHighs     []uint
		DownHighBytes []uint
		UpHighs       []uint
		UpHighBytes   []uint
	}{
		f.header,
		f.intervalMS,
		f.firstPacketTS,
		f.lastPacketTS,
		f.downBytes,
		f.upBytes,
		f.downPackets,
		f.upPackets,
		f.downZeros,
		f.upZeros,
		f.downMids,
		f.downMidBytes,
		f.upMids,
		f.upMidBytes,
		f.downHighs,
		f.downHighBytes,
		f.upHighs,
		f.upHighBytes,
	})
}

func (f *FlowPrint) Update(p common.Packet, idx int) {
	if p.IsOutbound {
		f.upPackets[idx]++
		f.upBytes[idx] += p.TotalLen

		if len(p.Payload) == 0 {
			f.upZeros[idx]++
		} else if len(p.Payload) > 1250 {
			f.upHighs[idx]++
			f.upHighBytes[idx] += uint(len(p.Payload))
		} else {
			f.upMids[idx]++
			f.upMidBytes[idx] += uint(len(p.Payload))
		}
	} else {
		f.downPackets[idx]++
		f.downBytes[idx] += p.TotalLen

		if len(p.Payload) == 0 {
			f.downZeros[idx]++
		} else if len(p.Payload) > 1250 {
			f.downHighs[idx]++
			f.downHighBytes[idx] += uint(len(p.Payload))
		} else {
			f.downMids[idx]++
			f.downMidBytes[idx] += uint(len(p.Payload))
		}
	}
}
