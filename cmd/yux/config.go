package main

import (
	"flag"

	"github.com/rs/zerolog/log"
	"github.com/spf13/pflag"
	"github.com/spf13/viper"
)

func OverridingFlags() {
	flag.String("log.level", "debug", "Log level for logger")
	flag.String("packets.source", "", "Interface to read packets from")
	flag.String("packets.bpf", "", "BPF to filter packets")
	flag.Int("packets.maxcount", 0, "Max packets to parse (0 => all)")
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
