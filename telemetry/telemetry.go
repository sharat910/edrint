package telemetry

import (
	"github.com/sharat910/edrint/common"
	"github.com/sharat910/edrint/events"
)

type TeleGen func() Telemetry

type Telemetry interface {
	Name() string
	OnFlowPacket(p common.Packet)
	SetPubFunc(pf events.PubFunc)
	SetHeader(header common.FiveTuple)
	Pubs() []events.Topic
	Init()
	Teardown()
}

type BaseFlowTelemetry struct {
	pf     events.PubFunc
	header common.FiveTuple
}

func (bt *BaseFlowTelemetry) SetPubFunc(pf events.PubFunc) { bt.pf = pf }
func (bt *BaseFlowTelemetry) Name() string                 { return "base_telemetry" }
func (bt *BaseFlowTelemetry) String() string               { return bt.Name() }
func (bt *BaseFlowTelemetry) Init()                        {}
func (bt *BaseFlowTelemetry) Teardown()                    {}
func (bt *BaseFlowTelemetry) Publish(topic events.Topic, event interface{}) {
	bt.pf(topic, event)
}
func (bt *BaseFlowTelemetry) SetHeader(header common.FiveTuple) { bt.header = header }
