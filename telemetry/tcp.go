package telemetry

import (
	"fmt"
	"math"
	"time"

	"github.com/rs/zerolog/log"
	"github.com/sharat910/edrint/common"
	"github.com/sharat910/edrint/events"
)

type TCPRetransmit struct {
	BaseFlowTelemetry
	firstPacketSeen bool
	firstPacketTS   time.Time
	lastPacketTS    time.Time
	intervalMS      int
	MaxSeqUp        uint32
	MaxSeqDown      uint32
	RetransmitsUp   []int
	RetransmitsDown []int

	CurIdx           int
	ProcessedPackets uint
	ProcessingTime   time.Duration
}

func (tsl *TCPRetransmit) Pubs() []events.Topic {
	return []events.Topic{events.TELEMETRY_TCP_RETRANSMIT}
}

func NewTCPRetransmit(intervalMS int) TeleGen {
	if intervalMS == 0 {
		log.Warn().Msg("tcp_retransmit_simple unable to read intervalMS. Setting default: 1sec")
		intervalMS = 1000
	}
	return func() Telemetry {
		var t TCPRetransmit
		t.intervalMS = intervalMS
		log.Debug().Str("telemetry", t.Name()).Int("intervalMS", intervalMS).Msg("config")
		return &t
	}
}

func (tsl *TCPRetransmit) Name() string {
	return "tcp_retransmit_simple"
}

func (tsl *TCPRetransmit) OnFlowPacket(p common.Packet) {
	defer func(start time.Time) {
		tsl.ProcessedPackets++
		tsl.ProcessingTime += time.Since(start)
	}(time.Now())

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

func (tsl *TCPRetransmit) ExtendUntil(idx int) {
	for i := len(tsl.RetransmitsDown); i <= idx; i++ {
		tsl.RetransmitsDown = append(tsl.RetransmitsDown, 0)
		tsl.RetransmitsUp = append(tsl.RetransmitsUp, 0)
	}
}

func (tsl *TCPRetransmit) Teardown() {
	log.Debug().Str("processing_time", tsl.ProcessingTime.String()).Uint("packets", tsl.ProcessedPackets).
		Str("telemetry", tsl.Name()).Str("header", fmt.Sprint(tsl.header)).Msg("teardown")
	tsl.Publish(events.TELEMETRY_TCP_RETRANSMIT, struct {
		FirstPacketTS   time.Time
		LastPacketTS    time.Time
		IntervalMS      int
		Header          common.FiveTuple
		RetransmitsUp   []int
		RetransmitsDown []int
	}{tsl.firstPacketTS,
		tsl.lastPacketTS,
		tsl.intervalMS,
		tsl.header,
		tsl.RetransmitsUp,
		tsl.RetransmitsDown,
	})
}

func (tsl *TCPRetransmit) IncRetransmitCounters(p common.Packet, idx int) {
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

type RTTEntry struct {
	Timestamp  time.Time
	PayloadLen uint32
	Ignore     bool
}

type TCPRTT struct {
	BaseFlowTelemetry
	firstPacketSeen bool
	firstPacketTS   time.Time
	lastPacketTS    time.Time
	m               map[uint32]*RTTEntry
	nextExpSeq      uint32
	OOOLeft         uint32
	OOORight        uint32
	lossSeen        bool

	RelTimestampMS []uint
	RTTMS          []uint

	DC RTTDebugCounters
}

func (tr *TCPRTT) Pubs() []events.Topic {
	return []events.Topic{events.TELEMETRY_TCP_RTT}
}

type RTTDebugCounters struct {
	ProcessingTime     time.Duration
	EntriesInserted    uint
	RTTSamplesProduced uint
	AcksIgnored        uint
	StaleEntries       uint
	ProcessedPackets   uint
}

func NewTCPRTT() TeleGen {
	return func() Telemetry {
		return &TCPRTT{m: make(map[uint32]*RTTEntry)}
	}
}

func (tr *TCPRTT) OnFlowPacket(p common.Packet) {
	defer func(start time.Time) {
		tr.DC.ProcessedPackets++
		tr.DC.ProcessingTime += time.Since(start)
	}(time.Now())

	if p.IsOutbound {
		if len(p.Payload) == 0 {
			if p.TCPLayer.SYN {
				log.Debug().Time("t", p.Timestamp).Uint32("seq", p.TCPLayer.Seq).Str("header", fmt.Sprint(p.GetKey())).Msg("syn")
				eack := p.TCPLayer.Seq + 1
				tr.m[eack] = &RTTEntry{Timestamp: p.Timestamp}
				tr.nextExpSeq = eack
				tr.firstPacketTS = p.Timestamp
				tr.firstPacketSeen = true
			}
			return
		}
		//log.Debug().Time("t", p.Timestamp).Uint32("seq", p.TCPLayer.Seq).Str("header", fmt.Sprint(p.GetKey())).Msg("upload with data")
		if !tr.firstPacketSeen {
			tr.nextExpSeq = p.TCPLayer.Seq
			tr.firstPacketTS = p.Timestamp
			tr.firstPacketSeen = true
		}
		tr.lastPacketTS = p.Timestamp

		pLen := uint32(len(p.Payload))
		eack := p.TCPLayer.Seq + pLen
		re, exists := tr.m[eack]
		if exists {
			log.Warn().Time("tstamp", p.Timestamp).
				Uint32("seq", p.TCPLayer.Seq).
				Msg("not ignoring retransmitted upload packet")
			//re.Ignore = true
			return
		}
		re = &RTTEntry{Timestamp: p.Timestamp, PayloadLen: pLen}
		tr.m[eack] = re
		tr.DC.EntriesInserted++

		// Received packet is expected
		if p.TCPLayer.Seq == tr.nextExpSeq {

			tr.nextExpSeq = eack

			if tr.lossSeen {
				re.Ignore = true
				if tr.nextExpSeq == tr.OOOLeft {
					tr.nextExpSeq = tr.OOORight
					tr.lossSeen = false
				}
			}

		} else if p.TCPLayer.Seq > tr.nextExpSeq { // missing packet (has to be retransmitted) hence ignore current packet
			re.Ignore = true
			if !tr.lossSeen {
				tr.OOOLeft = p.TCPLayer.Seq
				tr.OOORight = eack
				tr.lossSeen = true
			} else {
				if p.TCPLayer.Seq < tr.OOOLeft {
					tr.OOOLeft = p.TCPLayer.Seq
				}

				if p.TCPLayer.Seq >= tr.OOORight {
					tr.OOORight = eack
				}
			}
		} else { // re-ordered packet
			re.Ignore = true
		}
		//log.Debug().Time("t", p.Timestamp).Uint32("seq", p.TCPLayer.Seq).Str("header", fmt.Sprint(p.GetKey())).
		//	Uint32("eack", eack).Str("rttentry", fmt.Sprint(re)).Msg("upload with data")

	} else { // Downstream packet
		if !p.TCPLayer.ACK { // If not acking -- don't care
			return
		}

		re, exists := tr.m[p.TCPLayer.Ack]
		if !exists {
			return
		}

		if re.Ignore {
			//log.Debug().Time("t", p.Timestamp).Str("header", fmt.Sprint(p.GetKey())).
			//	Uint32("ack", p.TCPLayer.Ack).Dur("rtt", p.Timestamp.Sub(re.Timestamp)).
			//	Msg("ignoring rtt_sample")
			tr.DC.AcksIgnored++
			delete(tr.m, p.TCPLayer.Ack)
			return
		}

		tr.AddRTTSample(p, re)
		delete(tr.m, p.TCPLayer.Ack)
	}
}

func (tr *TCPRTT) AddRTTSample(p common.Packet, re *RTTEntry) {
	log.Debug().Time("t", p.Timestamp).Str("header", fmt.Sprint(p.GetKey())).Uint32("ack", p.TCPLayer.Ack).
		Dur("rtt", p.Timestamp.Sub(re.Timestamp)).Msg("rtt_sample")

	tr.RTTMS = append(tr.RTTMS, uint(p.Timestamp.Sub(re.Timestamp)/time.Millisecond))
	tr.RelTimestampMS = append(tr.RelTimestampMS, uint(p.Timestamp.Sub(tr.firstPacketTS)/time.Millisecond))
	tr.DC.RTTSamplesProduced++
}

func (tr *TCPRTT) Teardown() {
	tr.DC.StaleEntries = uint(len(tr.m))
	log.Debug().Str("stats", fmt.Sprintf("%+v", tr.DC)).Str("telemetry", "tcp_rtt").Msg("teardown")
	tr.Publish(events.TELEMETRY_TCP_RTT, struct {
		FirstPacketTS  time.Time
		LastPacketTS   time.Time
		Header         common.FiveTuple
		RelTimestampMS []uint
		RTTMS          []uint
	}{
		tr.firstPacketTS,
		tr.lastPacketTS,
		tr.header,
		tr.RelTimestampMS,
		tr.RTTMS,
	})
}
