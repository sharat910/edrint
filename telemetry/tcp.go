package telemetry

import (
	"fmt"
	"math"
	"time"

	"github.com/rs/zerolog/log"
	"github.com/sharat910/edrint/eventbus"
	"github.com/sharat910/edrint/packets"
	"github.com/spf13/viper"
)

type TCPRetransmitSimple struct {
	BaseFlowTelemetry
	firstPacketSeen bool
	firstPacketTS   time.Time
	lastPacketTS    time.Time
	intervalMS      int
	MaxSeqUp        uint32
	MaxSeqDown      uint32
	RetransmitsUp   []int
	RetransmitsDown []int

	CurIdx int
}

type EventTCPRetransmitSimple struct {
	FirstPacketTS   time.Time
	LastPacketTS    time.Time
	IntervalMS      int
	Header          packets.FiveTuple
	RetransmitsUp   []int
	RetransmitsDown []int
}

func NewTCPRetransmitSimple() *TCPRetransmitSimple {
	var t TCPRetransmitSimple
	interval := viper.GetInt(fmt.Sprintf("telemetry.%s.interval_ms", t.Name()))
	if interval == 0 {
		log.Warn().Msg("tcp_retransmit_simple unable to read interval. Setting default: 1sec")
		interval = 1000
	}
	log.Debug().Str("telemetry", t.Name()).Int("interval", interval).Msg("config")
	t.intervalMS = interval
	return &t
}

func (tsl *TCPRetransmitSimple) Name() string {
	return "tcp_retransmit_simple"
}

func (tsl *TCPRetransmitSimple) OnFlowPacket(p packets.Packet) {
	if !tsl.firstPacketSeen {
		tsl.firstPacketTS = p.Timestamp
		tsl.firstPacketSeen = true
	}
	idx, err := GetIndex(tsl.firstPacketTS, p.Timestamp, tsl.intervalMS)
	if err != nil {
		log.Warn().Err(err).Str("telemetry", tsl.Name()).Msg("get_index throwing err")
		return
	}
	tsl.ExtendUntil(idx)
	tsl.IncRetransmitCounters(p, idx)
	tsl.lastPacketTS = p.Timestamp
}

func (tsl *TCPRetransmitSimple) ExtendUntil(idx int) {
	for i := len(tsl.RetransmitsDown); i <= idx; i++ {
		tsl.RetransmitsDown = append(tsl.RetransmitsDown, 0)
		tsl.RetransmitsUp = append(tsl.RetransmitsUp, 0)
	}
}

func (tsl *TCPRetransmitSimple) Teardown() {
	log.Debug().Str("telemetry", tsl.Name()).Msg("teardown")
	tsl.Publish(eventbus.Topic("telemetry."+tsl.Name()), EventTCPRetransmitSimple{
		FirstPacketTS:   tsl.firstPacketTS,
		LastPacketTS:    tsl.lastPacketTS,
		IntervalMS:      tsl.intervalMS,
		Header:          tsl.header,
		RetransmitsUp:   tsl.RetransmitsUp,
		RetransmitsDown: tsl.RetransmitsDown,
	})
}

func (tsl *TCPRetransmitSimple) IncRetransmitCounters(p packets.Packet, idx int) {
	if p.IsOutbound {
		if p.TCPLayer.Seq >= tsl.MaxSeqUp {
			tsl.MaxSeqUp = p.TCPLayer.Seq
		} else { // seq less than max seq, filling the hole

			// Check for overflow
			if tsl.MaxSeqUp-p.TCPLayer.Seq > math.MaxUint32/2 {
				tsl.MaxSeqUp = p.TCPLayer.Seq
				return
			}

			// Packet retransmit
			tsl.RetransmitsUp[idx]++
		}
	} else {

		if p.TCPLayer.Seq >= tsl.MaxSeqDown {
			tsl.MaxSeqDown = p.TCPLayer.Seq
		} else { // seq less than max seq, filling the hole

			// Check for overflow -- approx check
			if tsl.MaxSeqDown-p.TCPLayer.Seq > math.MaxUint32/2 {
				tsl.MaxSeqDown = p.TCPLayer.Seq
				return
			}

			// Packet retransmit
			tsl.RetransmitsDown[idx]++
		}
	}
}
