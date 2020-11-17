package processor

import (
	"encoding/json"
	"fmt"

	"github.com/rs/zerolog/log"
	"github.com/sharat910/edrint/common"
	"github.com/sharat910/edrint/events"
	"github.com/sharat910/edrint/telemetry"
)

type TelemetryManager struct {
	BasePublisher
	Classes map[string][]telemetry.TeleGen
}

func NewTelemetryManager() *TelemetryManager {
	return &TelemetryManager{
		Classes: make(map[string][]telemetry.TeleGen),
	}
}

func (tm *TelemetryManager) AddTFToClass(class string, tfgen telemetry.TeleGen) {
	tm.Classes[class] = append(tm.Classes[class], tfgen)
}

func (tm *TelemetryManager) Name() string {
	return "telemetry_manager"
}

func (tm *TelemetryManager) Init() {
	log.Debug().Str("proc", tm.Name()).Str("classes", fmt.Sprint(tm.Classes)).Msg("Init")
}

func (tm *TelemetryManager) Subs() []events.Topic {
	return []events.Topic{events.CLASSIFICATION}
}

func (tm *TelemetryManager) Pubs() []events.Topic {
	pubMap := map[events.Topic]struct{}{
		events.FLOW_ATTACH_TELEMETRY: {},
	}
	for _, tfgens := range tm.Classes {
		for _, tfgen := range tfgens {
			tf := tfgen()
			for _, pub := range tf.Pubs() {
				pubMap[pub] = struct{}{}
			}
		}
	}
	var pubs []events.Topic
	for pub := range pubMap {
		pubs = append(pubs, pub)
	}
	return pubs
}

func (tm *TelemetryManager) EventHandler(topic events.Topic, event interface{}) {
	switch topic {
	case events.CLASSIFICATION:
		clf := event.(EventClassification)
		var tfs []telemetry.Telemetry
		for _, tfgen := range tm.Classes[clf.Class] {
			tf := tfgen()
			tf.SetPubFunc(tm.pf)
			tf.SetHeader(clf.Header)
			tfs = append(tfs, tf)
		}

		if len(tfs) != 0 {
			tm.Publish(events.FLOW_ATTACH_TELEMETRY, EventAttachPerFlowTelemetry{
				Header:             clf.Header,
				TelemetryFunctions: tfs,
			})
		}
	}
}

type EventAttachPerFlowTelemetry struct {
	Header             common.FiveTuple
	TelemetryFunctions []telemetry.Telemetry
}

func (e EventAttachPerFlowTelemetry) MarshalJSON() ([]byte, error) {
	tfNames := make([]string, len(e.TelemetryFunctions))
	for i, tf := range e.TelemetryFunctions {
		tfNames[i] = tf.Name()
	}
	return json.Marshal(struct {
		Header             common.FiveTuple
		TelemetryFunctions []string
	}{
		e.Header,
		tfNames,
	})
}
