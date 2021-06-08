package main

import (
	"fmt"

	"github.com/sharat910/edrint/common"
	"github.com/sharat910/edrint/events"
	"github.com/sharat910/edrint/telemetry"
)

type LossComputer struct {
	telemetry.BaseFlowTelemetry
	UpSeqNumExpected uint8
	TotalLoss        int
}

func (l *LossComputer) Name() string {
	return "loss_computer"
}

func (l *LossComputer) OnFlowPacket(p common.Packet) {
	if p.IsOutbound {
		seq := l.ExtractSeqNum(p)
		if seq == l.UpSeqNumExpected {
			l.UpSeqNumExpected++
		} else {
			l.TotalLoss += int(seq - l.UpSeqNumExpected)
			fmt.Println(l.TotalLoss)
		}
	}
}

func (l *LossComputer) ExtractSeqNum(p common.Packet) uint8 {
	if p.IsOutbound {
		return p.Payload[3]
	} else {
		return p.Payload[5]
	}
}

func (l *LossComputer) Pubs() []events.Topic {
	return []events.Topic{"zoom_loss"}
}

func (l *LossComputer) Teardown() {
	l.Publish("zoom_loss", struct {
		Header    common.FiveTuple
		TotalLoss int
	}{
		l.GetHeader(),
		l.TotalLoss,
	})
}
