package telemetry

import (
	"fmt"
	"time"

	"github.com/montanaflynn/stats"
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
		log.Info().Str("header", cd.header.String()).Str("gap_chunk", fmt.Sprintf("%+v", cd.Chunks[len(cd.Chunks)-1])).Send()
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
	ReqLen                             int
	Bytes                              int
	Packets                            int
	Start                              time.Time
	End                                time.Time
	Request                            time.Time
	IPTs                               []float64 `json:"-"`
	Min, Max, Mean, STD, Q25, Q50, Q75 float64   `json:"-"`
}

func (h HTTPChunk) String() string {
	return fmt.Sprintf("Req: %d ChunkSize: %d Start: %s Dur: %s", h.ReqLen, h.Bytes, h.Start.String(), h.End.Sub(h.Start).String())
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
	if h.StartTime.IsZero() {
		h.StartTime = p.Timestamp
	}
	h.EndTime = p.Timestamp
	pLen := len(p.Payload)
	if pLen == 0 {
		return
	}
	if p.IsOutbound {
		if pLen > h.ReqThreshold {
			if len(h.Chunks) > 0 {
				lastIdx := len(h.Chunks) - 1
				//h.ComputeIPTStats(lastIdx)
				log.Debug().Str("ft", h.GetHeader().String()).Str("chunk", h.Chunks[lastIdx].String()).Msg("chunk")
			}
			h.Chunks = append(h.Chunks, HTTPChunk{
				ReqLen:  pLen,
				Request: p.Timestamp,
			})
		} else {
			log.Debug().Str("ft", h.header.String()).Int("req_thresh", h.ReqThreshold).
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
		end := h.Chunks[lastIdx].End
		if !end.IsZero() {

			h.Chunks[lastIdx].IPTs = append(h.Chunks[lastIdx].IPTs, p.Timestamp.Sub(end).Seconds())

			if p.Timestamp.After(h.Chunks[lastIdx].End.Add(200 * time.Millisecond)) {
				log.Warn().Int("chunk_idx", len(h.Chunks)-1).Time("last", end).
					Str("delta", p.Timestamp.Sub(h.Chunks[lastIdx].End).String()).
					Int("pLen", pLen).Str("last_chunk", h.Chunks[lastIdx].String()).
					Str("ft", h.GetHeader().String()).Msg("download packet after")
			}
		}
		h.Chunks[lastIdx].End = p.Timestamp
		h.Chunks[lastIdx].Packets++
		h.Chunks[lastIdx].Bytes += len(p.Payload)
	}
}

func (h *HTTPChunkDetector) ComputeIPTStats(idx int) {
	var err error
	if len(h.Chunks[idx].IPTs) > 1 {
		h.Chunks[idx].Min, err = stats.Min(h.Chunks[idx].IPTs)
		if err != nil {
			log.Warn().Err(err).Msg("stats error")
		}
		h.Chunks[idx].Max, err = stats.Max(h.Chunks[idx].IPTs)
		if err != nil {
			log.Warn().Err(err).Msg("stats error")
		}
		h.Chunks[idx].Mean, err = stats.Mean(h.Chunks[idx].IPTs)
		if err != nil {
			log.Warn().Err(err).Msg("stats error")
		}
		h.Chunks[idx].STD, err = stats.StandardDeviation(h.Chunks[idx].IPTs)
		if err != nil {
			log.Warn().Err(err).Msg("stats error")
		}
		q, err := stats.Quartile(h.Chunks[idx].IPTs)
		if err != nil {
			log.Warn().Err(err).Msg("stats error")
		}
		h.Chunks[idx].Q25 = q.Q1
		h.Chunks[idx].Q50 = q.Q2
		h.Chunks[idx].Q75 = q.Q3
	}
}

func (h *HTTPChunkDetector) Pubs() []events.Topic {
	return []events.Topic{events.TELEMETRY_HTTP_CHUNK}
}

func (h *HTTPChunkDetector) Teardown() {
	log.Info().Str("ft", h.header.String()).Int("num_chunks", len(h.Chunks)).Msg("chunks in a flow")
	h.Publish(events.TELEMETRY_HTTP_CHUNK, struct {
		Header       common.FiveTuple
		StartTime    time.Time
		EndTime      time.Time
		ReqThreshold int
		NumChunks    int
		Chunks       []HTTPChunk
	}{h.header, h.StartTime, h.EndTime, h.ReqThreshold, len(h.Chunks), h.Chunks})
}
