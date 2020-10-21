package main

import (
	"flag"

	"github.com/rs/zerolog/log"
	"github.com/spf13/pflag"
	"github.com/spf13/viper"
)

func OverridingFlags() {
	flag.String("log.level", "debug", "Log level for logger")
	flag.String("packets.interface", "eth1", "Interface to read packets from")
	flag.String("packets.pcap_path", "no-path.pcap", "Interface to read packets from")
}

func SetupConfig() {
	OverridingFlags()
	viper.AddConfigPath(".")
	viper.SetConfigName("config")
	pflag.CommandLine.AddGoFlagSet(flag.CommandLine)
	pflag.Parse()
	err := viper.BindPFlags(pflag.CommandLine)
	if err != nil {
		log.Fatal().Err(err).Msg("unable to bind pflags")
	}
	err = viper.ReadInConfig()
	if err != nil {
		log.Fatal().Err(err).Msg("unable to read config")
	}
}
