package processor

import (
	"fmt"

	"github.com/rs/zerolog/log"
	"github.com/sharat910/edrint/eventbus"
	"github.com/spf13/viper"
)

type Processor interface {
	Name() string
	Subs() []eventbus.Topic
	Pubs() []eventbus.Topic
	EventHandler(topic eventbus.Topic, event interface{})
	SetEventBus(eb *eventbus.EventBus)
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

func (b BaseProcessor) SetEventBus(eb *eventbus.EventBus) {}
func (b BaseSubscriber) Pubs() []eventbus.Topic           { return nil }

type BasePublisher struct {
	BaseProcessor
	eb *eventbus.EventBus
}

func (b *BasePublisher) SetEventBus(eb *eventbus.EventBus)               { b.eb = eb }
func (b *BasePublisher) Publish(topic eventbus.Topic, event interface{}) { b.eb.Publish(topic, event) }

func GetProcsFromConfig() []Processor {
	var processors []Processor
	procs := viper.GetStringMap("processors")
	for procName := range procs {
		if viper.GetBool(fmt.Sprintf("processors.%s.enabled", procName)) {
			log.Info().Str("proc", procName).Msg("processor added")
			proc := GetByName(procName)
			if proc == nil {
				log.Fatal().Str("proc", procName).Msg("unable to get proc (did you add to proc factory?)")
			}
			processors = append(processors, proc)
		}
	}
	return processors
}

func GetByName(name string) Processor {
	switch name {
	case "flow":
		return NewFlowProcessor()
	case "dump":
		return NewDumper()
	case "dns":
		return NewDNSParser()
	case "sni":
		return NewSNIParser()
	case "telemetry_manager":
		return NewTelemetryManager()
	case "header_classifier":
		return NewHeaderClassifer()
	default:
		log.Warn().Str("name", name).Msg("Unknown processor")
		return nil
	}
}
