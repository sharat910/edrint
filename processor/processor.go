package processor

import (
	"github.com/sharat910/edrint/events"
)

type Processor interface {
	Name() string
	Subs() []events.Topic
	Pubs() []events.Topic
	EventHandler(topic events.Topic, event interface{})
	SetPubFunc(f events.PubFunc)
	Init()
	Teardown()
}

type BaseProcessor struct {
}

func (b BaseProcessor) Init()     {}
func (b BaseProcessor) Teardown() {}

type BaseSubscriber struct {
	BaseProcessor
}

func (b BaseProcessor) SetPubFunc(pf events.PubFunc) {}
func (b BaseSubscriber) Pubs() []events.Topic        { return nil }

type BasePublisher struct {
	BaseProcessor
	pf events.PubFunc
}

func (b *BasePublisher) SetPubFunc(f events.PubFunc)                   { b.pf = f }
func (b *BasePublisher) Publish(topic events.Topic, event interface{}) { b.pf(topic, event) }
