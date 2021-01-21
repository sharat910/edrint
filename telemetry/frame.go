package telemetry

import (
	"time"

	"github.com/sharat910/edrint/common"
	"github.com/sharat910/edrint/events"
)

type FrameDetector struct {
	BaseFlowTelemetry
	CurFrameSize    int
	CurFramePackets int
	CurFrameStart   time.Time
	CurFrameEnd     time.Time
}

func NewFrameDetector() TeleGen {
	var fd FrameDetector
	return func() Telemetry {
		return &fd
	}
}

func (f *FrameDetector) Name() string {
	return "frame_detector"
}

func (f *FrameDetector) OnFlowPacket(p common.Packet) {
	if p.IsOutbound {
		return
	}

	b := p.Payload[2]

	if b == 128 {
		// Frame demarcation
		if f.CurFramePackets != 0 {
			f.ExportAndReset()
		}
		f.CurFrameStart = p.Timestamp
		f.CurFrameEnd = p.Timestamp
	} else if b == 160 {
		f.CurFrameEnd = p.Timestamp
		f.CurFrameSize += len(p.Payload)
		f.CurFramePackets++
	}
}

func (f *FrameDetector) Pubs() []events.Topic {
	return []events.Topic{"telemetry.frame"}
}

func (f *FrameDetector) ExportAndReset() {
	f.Publish("telemetry.frame", struct {
		FrameStart   time.Time
		FrameEnd     time.Time
		FrameSize    int
		FramePackets int
	}{
		f.CurFrameStart,
		f.CurFrameEnd,
		f.CurFrameSize,
		f.CurFramePackets,
	})

	f.CurFrameSize = 0
	f.CurFramePackets = 0
}
