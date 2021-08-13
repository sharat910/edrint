package telemetry

import (
	"time"

	"github.com/rs/zerolog/log"

	"github.com/montanaflynn/stats"
	"github.com/sharat910/edrint/common"
	"github.com/sharat910/edrint/events"
)

type HTTPReqIsolator struct {
	BaseFlowTelemetry
	StartTime     time.Time
	EndTime       time.Time
	Threshold     int
	RequestLens   []float64
	LastPacketReq bool
}

func NewHTTPReqIsolator(reqThreshold int) TeleGen {
	return func() Telemetry {
		return &HTTPReqIsolator{Threshold: reqThreshold}
	}
}

type ReqStats struct {
	Count, Mean, Max, Min, Q1, Q2, Q3 float64
}

func (h *HTTPReqIsolator) Name() string {
	return "http_req_isolator"
}

func (h *HTTPReqIsolator) OnFlowPacket(p common.Packet) {
	if p.IsOutbound {
		if h.StartTime.IsZero() {
			h.StartTime = p.Timestamp
		}
		h.EndTime = p.Timestamp
		pldLen := len(p.Payload)
		if pldLen >= h.Threshold {
			h.RequestLens = append(h.RequestLens, float64(pldLen))
			//fmt.Println("REQ", pldLen, binary.BigEndian.Uint16(p.Payload[3:5]), p.Payload[:10], p.Header)
			//h.LastPacketReq = true
		}
		//if pldLen > 150 && pldLen < 400 {
		//	sni, _ := ExtractTCPSNI(p.Payload)
		//
		//}
	} else {
		//pldLen := len(p.Payload)
		//if h.LastPacketReq && pldLen > 5 {
		//	if p.Payload[0] == 0x17 && p.Payload[1] == 0x03 && p.Payload[2] == 0x03 {
		//		fmt.Println("RESP", h.RequestLens[len(h.RequestLens)-1], pldLen, binary.BigEndian.Uint16(p.Payload[3:5]), p.Payload[:10], p.Header)
		//	}
		//	//h.LastPacketReq = false
		//}
	}
}

func (h *HTTPReqIsolator) Pubs() []events.Topic {
	return []events.Topic{events.TELEMETRY_HTTP_REQ}
}

func (h *HTTPReqIsolator) Teardown() {
	if len(h.RequestLens) == 0 {
		return
	}
	data := struct {
		Header       common.FiveTuple
		StartTime    time.Time
		Duration     float64
		ReqThreshold int
		ReqStats     ReqStats
	}{h.header, h.StartTime, h.EndTime.Sub(h.StartTime).Seconds(), h.Threshold, h.GetReqStats()}
	log.Debug().Interface("data", data).Send()
	if data.ReqStats.Min < 400 {
		log.Warn().Interface("data", data).Msg("small req")
	}
	//h.Publish(events.TELEMETRY_HTTP_REQ, data)
}

func (h *HTTPReqIsolator) GetReqStats() (rs ReqStats) {
	if len(h.RequestLens) == 0 {
		return
	}
	rs.Count = float64(len(h.RequestLens))
	var err error
	rs.Mean, err = stats.Mean(h.RequestLens)
	if err != nil {
		log.Fatal().Err(err).Send()
	}
	rs.Min, err = stats.Min(h.RequestLens)
	if err != nil {
		log.Fatal().Err(err).Send()
	}
	rs.Max, err = stats.Max(h.RequestLens)
	if err != nil {
		log.Fatal().Err(err).Send()
	}
	q, err := stats.Quartile(h.RequestLens)
	if err != nil {
		log.Fatal().Err(err).Send()
	}
	rs.Q1 = q.Q1
	rs.Q2 = q.Q2
	rs.Q3 = q.Q3
	return
}

func ExtractTCPSNI(payload []byte) (string, bool) {
	pLen := len(payload)
	var serverName string
	// Check if the packet is a Client Hello
	if !(pLen > 6 && payload[0] == 0x16 && payload[5] == 0x01) {
		return serverName, false
	}
	sessionIdLength := int((payload[43:44])[0])
	// Start after <Session ID Length>
	index := 44

	// Skip over <Session IDs>
	index += sessionIdLength

	// Extract <Cipher Suite Length>
	cipherSuiteLength := bytesToInt16(payload[index : index+2])

	// Skip over <Cipher Suite Length>
	index += 2
	// Skip over <Cipher Suites>
	index += cipherSuiteLength

	if index >= pLen {
		return serverName, false
	}
	// Extract <Compression Methods Length>
	compressionMethodsLength := int(payload[index])
	// SKip over compression methods length field and compression lengths itself
	index += 1
	index += compressionMethodsLength

	// Extract <Extensions Length>
	extensionsLength := bytesToInt16(payload[index : index+2])
	// Skip over <Extensions Length>
	index += 2
	if index >= pLen {
		return serverName, false
	}
	for index < len(payload) {
		extensionCode := bytesToInt16(payload[index : index+2])
		index += 2
		if index >= pLen {
			return serverName, false
		}
		if extensionCode == 0 {
			serverNameLength := bytesToInt16(payload[index : index+2])
			serverNameLength -= 2
			index += 4
			if index >= pLen {
				return serverName, false
			}
			if int(payload[index]) == 0 {
				serverNameLength -= 3
				index += 3
				serverName = string(payload[index : index+serverNameLength])
				break
			}
		} else {
			extensionsLength = bytesToInt16(payload[index : index+2])
			index += 2
			index += extensionsLength
		}
	}
	return serverName, true
}

func bytesToInt16(byteSlice []byte) int {
	return int(byteSlice[0])<<8 + int(byteSlice[1])
}
