package main

import (
	"fmt"
	"path/filepath"

	"github.com/sharat910/edrint/telemetry"

	"github.com/sharat910/edrint/events"

	"github.com/rs/zerolog/log"
	"github.com/sharat910/edrint"
	"github.com/sharat910/edrint/processor"
	"github.com/spf13/viper"
)

func main() {
	SetupConfig()
	edrint.SetupLogging(viper.GetString("log.level"))
	manager := edrint.New()
	manager.RegisterProc(processor.NewFlowProcessor(2))
	rules := GetClassificationRules()
	manager.RegisterProc(processor.NewHeaderClassifer(rules))

	teleManager := processor.NewTelemetryManager()
	teleManager.AddTFToClass("zoomtcp", telemetry.NewTCPRetransmit(1000))
	teleManager.AddTFToClass("amazonprime", telemetry.NewFlowSummary())
	teleManager.AddTFToClass("amazonprime", telemetry.NewHTTPChunkDetector(100))

	manager.RegisterProc(teleManager)

	manager.RegisterProc(processor.NewDumper(fmt.Sprintf("./files/dumps/%s.json.log",
		filepath.Base(viper.GetString("packets.source"))),
		[]events.Topic{
			events.TELEMETRY_TCP_RETRANSMIT,
			events.FLOW_ATTACH_TELEMETRY,
			events.TELEMETRY_FLOWSUMMARY,
			events.TELEMETRY_HTTP_CHUNK,
			"zoom_loss",
		}))

	err := manager.InitProcessors()
	if err != nil {
		log.Fatal().Err(err).Msg("init error")
	}
	err = manager.Run(edrint.ParserConfig{
		CapMode:    edrint.PCAPFILE,
		CapSource:  viper.GetString("packets.source"),
		DirMode:    edrint.CLIENT_IP,
		DirMatches: viper.GetStringSlice("packets.direction.client_ips"),
	})
	if err != nil {
		log.Fatal().Err(err).Msg("some error occurred")
	}
}

func GetClassificationRules() map[string]map[string]string {
	rules := make(map[string]map[string]string)
	config := viper.GetStringMap(fmt.Sprintf("processors.header_classifier.classes"))
	for class := range config {
		rules[class] = viper.GetStringMapString(fmt.Sprintf("processors.header_classifier.classes.%s", class))
	}
	return rules
}
