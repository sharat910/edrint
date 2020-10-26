package telemetry

import (
	"github.com/rs/zerolog/log"
	"github.com/sharat910/edrint/eventbus"
	"github.com/sharat910/edrint/packets"
)

type Telemetry interface {
	Name() string
	OnFlowPacket(p packets.Packet)
	SetEventBus(eb *eventbus.EventBus)
	SetHeader(header packets.FiveTuple)
	Init()
	Teardown()
}

type BaseFlowTelemetry struct {
	eb     *eventbus.EventBus
	header packets.FiveTuple
}

func (bt *BaseFlowTelemetry) SetEventBus(eb *eventbus.EventBus) { bt.eb = eb }
func (bt *BaseFlowTelemetry) Name() string                      { return "base_telemetry" }
func (bt *BaseFlowTelemetry) String() string                    { return bt.Name() }
func (bt *BaseFlowTelemetry) Init()                             {}
func (bt *BaseFlowTelemetry) Teardown()                         {}
func (bt *BaseFlowTelemetry) Publish(topic eventbus.Topic, event interface{}) {
	bt.eb.Publish(topic, event)
}
func (bt *BaseFlowTelemetry) SetHeader(header packets.FiveTuple) { bt.header = header }

func GetByName(name string, header packets.FiveTuple, eb *eventbus.EventBus) Telemetry {
	var t Telemetry
	switch name {
	case "tcp_retransmit_simple":
		t = NewTCPRetransmitSimple()
	case "flowpulse":
		t = NewFlowPulse()
	case "tcp_rtt":
		t = NewTCPRTT()
	default:
		log.Fatal().Str("telemetry", name).Msg("unknown telemetry requested")
	}
	if t != nil {
		t.SetHeader(header)
		t.SetEventBus(eb)
	}
	return t
}
