package main

import (
	"github.com/rs/zerolog/log"
	"github.com/sharat910/edrint/events"
	"github.com/sharat910/edrint/processor"
	"github.com/sharat910/edrint/telemetry"
)

type AFLCT struct {
	processor.BasePublisher
	flowlets []telemetry.Flowlet
}

func (A AFLCT) Name() string {
	return "aflct_computer"
}

func (A AFLCT) Subs() []events.Topic {
	return []events.Topic{events.TELEMETRY_FLOWLET}
}

func (A AFLCT) Pubs() []events.Topic {
	return []events.Topic{"aflct"}
}

func (A *AFLCT) EventHandler(topic events.Topic, event interface{}) {
	switch topic {
	case events.TELEMETRY_FLOWLET:
		flSummary := event.(telemetry.FlowletExport)
		A.flowlets = append(A.flowlets, flSummary.Flowlets...)
	}
}

func (A *AFLCT) Teardown() {
	totalVol := 0
	totalTime := 0
	var flowletSizes, flowletDurationsUS []int
	for _, fl := range A.flowlets {
		if fl.Packets < 5 {
			//log.Warn().Str("flowlet", fmt.Sprintf("%+v", fl)).Msg("small flowlet")
			continue
		}
		totalVol += fl.Bytes
		totalTime += fl.DurationUS
		flowletSizes = append(flowletSizes, fl.Bytes)
		flowletDurationsUS = append(flowletDurationsUS, fl.DurationUS)
	}
	if totalVol > 0 {
		normalizedAFLCT := 1e3 * totalTime / totalVol
		log.Info().Int("ns/b", normalizedAFLCT).Msg("aflct")
		A.Publish("aflct", struct {
			NormalizedAFLCT    int   `json:"normalized_aflct_ns_per_byte"`
			FlowletSizes       []int `json:"flowlet_sizes"`
			FlowletDurationsUS []int `json:"flowlet_durations_us"`
		}{normalizedAFLCT, flowletSizes, flowletDurationsUS})
	}
}
