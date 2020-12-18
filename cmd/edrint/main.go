package main

import (
	"fmt"
	"os"
	"path/filepath"
	"time"

	"github.com/sharat910/edrint/telemetry"

	"github.com/sharat910/edrint/events"

	"github.com/rs/zerolog/log"
	"github.com/sharat910/edrint"
	"github.com/sharat910/edrint/processor"
	"github.com/spf13/viper"
)

func main() {
	SetupConfig()
	edrint.SetupLogging("info")
	manager := edrint.New()
	manager.RegisterProc(processor.NewFlowProcessor(2))
	rules := GetClassificationRules()
	manager.RegisterProc(processor.NewHeaderClassifer(rules))

	teleManager := processor.NewTelemetryManager()
	//teleManager.AddTFToClass("https", telemetry.NewFlowPulse(100))
	teleManager.AddTFToClass("https", telemetry.NewGapChunkDetector(10*time.Millisecond))
	manager.RegisterProc(teleManager)

	manager.RegisterProc(processor.NewDumper("./files/dumps/dump.json.log",
		[]events.Topic{
			//events.FLOW_ATTACH_TELEMETRY,
			//events.TELEMETRY_FLOWPULSE,
			events.TELEMETRY_GAP_CHUNK,
		}))

	err := manager.InitProcessors()
	if err != nil {
		log.Fatal().Err(err).Msg("init error")
	}
	err = manager.Run(edrint.ParserConfig{
		CapMode:    edrint.PCAPFILE,
		CapSource:  viper.GetString("packets.source"),
		DirMode:    edrint.CLIENT_IP,
		DirMatches: []string{"172.23.0.2/24"},
	})
	if err != nil {
		log.Fatal().Err(err).Msg("some error occurred")
	}
	err = os.Rename("./files/dumps/dump.json.log", fmt.Sprintf("./files/dumps/%s.json.log", filepath.Base(viper.GetString("packets.source"))))
	if err != nil {
		log.Fatal().Err(err).Msg("")
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
