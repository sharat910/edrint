package main

import (
	"github.com/rs/zerolog/log"
	"github.com/sharat910/edrint/packets"
	"github.com/sharat910/edrint/processor"

	"github.com/sharat910/edrint/eventbus"

	"github.com/spf13/viper"
)

func main() {
	SetupConfig()
	SetupLogging(viper.GetString("log.level"))
	eb := eventbus.New()
	procs := processor.GetProcsFromConfig()
	for _, proc := range procs {

		// Initialize the processor
		proc.Init()

		// Subscribe to topics by passing proc's event handlers
		for _, topic := range proc.Subs() {
			log.Info().Str("proc", proc.Name()).Str("topic", string(topic)).Msg("subscription")
			eb.Subscribe(topic, proc.EventHandler)
		}

		// Pass eventbus to procs that publish
		if len(proc.Pubs()) > 0 {
			proc.SetEventBus(eb)
		}

	}
	// Start processing packets
	packets.PacketParser(eb)

	for _, proc := range procs {
		proc.Teardown()
	}
}
