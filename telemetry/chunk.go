package telemetry

import (
	"time"

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
