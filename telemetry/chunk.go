package telemetry

import (
	"time"

	"github.com/rs/zerolog/log"

	"github.com/sharat910/edrint/events"

	"github.com/sharat910/edrint/common"
)

type Chunk struct {
	ChunkStart   time.Time
	ChunkEnd     time.Time
	ChunkSize    int
	ChunkPackets int
	GapMS        int
}

type GapChunkDetector struct {
	BaseFlowTelemetry
	gap         time.Duration
	FirstDownTS time.Time
	LastDownTS  time.Time
	Chunks      []Chunk
}

func (cd *GapChunkDetector) Pubs() []events.Topic {
	return []events.Topic{events.TELEMETRY_GAP_CHUNK}
}

func NewGapChunkDetector(gap time.Duration) TeleGen {
	return func() Telemetry {
		return &GapChunkDetector{gap: gap}
	}
}

func (cd *GapChunkDetector) Name() string {
	return "gap_chunk_detector"
}

func (cd *GapChunkDetector) OnFlowPacket(p common.Packet) {
	if p.IsOutbound {
		return
	}

	if cd.FirstDownTS.IsZero() {
		cd.FirstDownTS = p.Timestamp
		cd.LastDownTS = p.Timestamp
		cd.Chunks = append(cd.Chunks, Chunk{})
		cd.Chunks[0].ChunkStart = p.Timestamp
	}

	if p.Timestamp.Sub(cd.LastDownTS) > cd.gap {
		cd.Chunks[len(cd.Chunks)-1].GapMS = int(p.Timestamp.Sub(cd.LastDownTS) / time.Millisecond)
		cd.Chunks = append(cd.Chunks, Chunk{})
		cd.Chunks[len(cd.Chunks)-1].ChunkStart = p.Timestamp
	}
	cd.Chunks[len(cd.Chunks)-1].ChunkEnd = p.Timestamp
	cd.Chunks[len(cd.Chunks)-1].ChunkSize += len(p.Payload)
	cd.Chunks[len(cd.Chunks)-1].ChunkPackets++
	cd.LastDownTS = p.Timestamp
}

func (cd *GapChunkDetector) Teardown() {
	cd.Publish(events.TELEMETRY_GAP_CHUNK, struct {
		Header      common.FiveTuple
		FirstDownTS time.Time
		Chunks      []Chunk
	}{cd.header, cd.FirstDownTS, cd.Chunks})
}

type HTTPChunk struct {
	ReqLen  int
	Bytes   int
	Packets int
	Start   time.Time
	End     time.Time
	Request time.Time
}

type HTTPChunkDetector struct {
	BaseFlowTelemetry
	ReqThreshold int
	Chunks       []HTTPChunk
	StartTime    time.Time
	EndTime      time.Time
}

func NewHTTPChunkDetector(reqThreshold int) TeleGen {
	return func() Telemetry {
		return &HTTPChunkDetector{ReqThreshold: reqThreshold}
	}
}

func (h *HTTPChunkDetector) Name() string {
	return "http_chunk_detector"
}

func (h *HTTPChunkDetector) OnFlowPacket(p common.Packet) {
	pLen := len(p.Payload)
	if pLen == 0 {
		return
	}
	if p.IsOutbound {
		if pLen > h.ReqThreshold {
			h.Chunks = append(h.Chunks, HTTPChunk{
				ReqLen:  pLen,
				Request: p.Timestamp,
			})
		} else {
			log.Warn().Str("ft", h.header.String()).Int("req_thresh", h.ReqThreshold).
				Int("pLen", pLen).Msg("upload packet < h.ReqThreshold")
		}
	} else {
		if len(h.Chunks) == 0 {
			return
		}
		lastIdx := len(h.Chunks) - 1
		if h.Chunks[lastIdx].Start.IsZero() {
			h.Chunks[lastIdx].Start = p.Timestamp
		}
		h.Chunks[lastIdx].End = p.Timestamp
		h.Chunks[lastIdx].Packets++
		h.Chunks[lastIdx].Bytes += len(p.Payload)
	}
}

func (h *HTTPChunkDetector) Pubs() []events.Topic {
	return []events.Topic{events.TELEMETRY_HTTP_CHUNK}
}

func (h *HTTPChunkDetector) Teardown() {
	h.Publish(events.TELEMETRY_HTTP_CHUNK, struct {
		Header       common.FiveTuple
		StartTime    time.Time
		EndTime      time.Time
		ReqThreshold int
		Chunks       []HTTPChunk
	}{h.header, h.StartTime, h.EndTime, h.ReqThreshold, h.Chunks})
}
