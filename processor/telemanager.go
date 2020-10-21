package processor

import (
	"encoding/json"
	"fmt"

	"github.com/rs/zerolog/log"
	"github.com/spf13/viper"

	"github.com/sharat910/edrint/eventbus"
	"github.com/sharat910/edrint/packets"
	"github.com/sharat910/edrint/telemetry"
)

type TelemetryManager struct {
	BasePublisher
	Classes map[string][]string
}

func NewTelemetryManager() *TelemetryManager {
	return &TelemetryManager{
		Classes: make(map[string][]string),
	}
}

func (tm *TelemetryManager) Name() string {
	return "telemetry_manager"
}

func (tm *TelemetryManager) Init() {
	tm.Classes = viper.GetStringMapStringSlice(fmt.Sprintf("processors.%s.classes", tm.Name()))
	log.Debug().Str("proc", tm.Name()).Str("classes", fmt.Sprint(tm.Classes)).Msg("Init")
}

func (tm *TelemetryManager) Subs() []eventbus.Topic {
	return []eventbus.Topic{"classification"}
}

func (tm *TelemetryManager) Pubs() []eventbus.Topic {
	return []eventbus.Topic{"flow.attach_telemetry"}
}

func (tm *TelemetryManager) EventHandler(topic eventbus.Topic, event interface{}) {
	switch topic {
	case "classification":
		clf := event.(EventClassification)
		var tfs []telemetry.Telemetry

		for _, tf := range tm.Classes[clf.Class] {
			tfs = append(tfs, telemetry.GetByName(tf, clf.Header, tm.eb))
		}

		if len(tfs) != 0 {
			tm.Publish("flow.attach_telemetry", EventAttachPerFlowTelemetry{
				Header:             clf.Header,
				TelemetryFunctions: tfs,
			})
		}
	}
}

type EventAttachPerFlowTelemetry struct {
	Header             packets.FiveTuple
	TelemetryFunctions []telemetry.Telemetry
}

func (e EventAttachPerFlowTelemetry) MarshalJSON() ([]byte, error) {
	tfNames := make([]string, len(e.TelemetryFunctions))
	for i, tf := range e.TelemetryFunctions {
		tfNames[i] = tf.Name()
	}
	return json.Marshal(struct {
		Header             packets.FiveTuple
		TelemetryFunctions []string
	}{
		e.Header,
		tfNames,
	})
}
