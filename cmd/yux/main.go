package main

import (
	"github.com/rs/zerolog/log"
	"github.com/sharat910/edrint"
	"github.com/sharat910/edrint/events"
	"github.com/sharat910/edrint/processor"
	"github.com/sharat910/edrint/telemetry"
	"github.com/spf13/viper"
)

func main() {
	SetupConfig()
	edrint.SetupLogging(viper.GetString("log.level"))
	manager := edrint.New()
	manager.RegisterProc(processor.NewFlowProcessor(2))
	manager.RegisterProc(processor.NewSNIParser())
	manager.RegisterProc(processor.NewSNIClassifier(viper.GetStringMapString("sniclassifier.classes")))
	teleManager := processor.NewTelemetryManager()
	teleManager.AddTFToClass("youtube", telemetry.NewHTTPChunkDetector(500))
	manager.RegisterProc(teleManager)

	dumpPath := "./files/dump.json.log"
	//dumpPath := fmt.Sprintf("%s/telemetry/%s.json.log",
	//	filepath.Dir(filepath.Dir(packetPath)), filepath.Base(packetPath))
	manager.RegisterProc(processor.NewDumper(dumpPath,
		[]events.Topic{
			events.TELEMETRY_HTTP_CHUNK,
			events.CLASSIFICATION,
		}, false))

	err := manager.InitProcessors()
	if err != nil {
		log.Fatal().Err(err).Msg("init error")
	}
	err = manager.Run(edrint.ParserConfig{
		CapMode:    edrint.INTERFACE,
		CapSource:  viper.GetString("packets.source"),
		DirMode:    edrint.CLIENT_IP,
		DirMatches: viper.GetStringSlice("packets.direction.client_ips"),
		BPF:        viper.GetString("packets.bpf"),
		MaxPackets: viper.GetInt("packets.maxcount"),
	})
	if err != nil {
		log.Fatal().Err(err).Msg("some error occurred")
	}
}
