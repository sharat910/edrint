package processor

import (
	"fmt"
	"time"

	"github.com/rs/zerolog/log"
	"github.com/sharat910/edrint/eventbus"
	"github.com/sharat910/edrint/packets"
	"github.com/sharat910/edrint/telemetry"
	"github.com/spf13/viper"
)

type FlowProcessor struct {
	BasePublisher
	m       map[packets.FiveTuple]*Entry
	latest  *Entry
	oldest  *Entry
	Timeout time.Duration

	// Counters
	nEntries uint
	nExpired uint
}

func (f *FlowProcessor) Teardown() {
	if f.latest != nil {
		f.expireEntries(f.latest.UpdatedTS.Add(f.Timeout))
	}
	log.Info().Str("proc", f.Name()).Int("entry_count", len(f.m)).Msg("teardown")
}

func NewFlowProcessor() *FlowProcessor {
	timeoutMin := viper.GetInt("processors.flow.timeout")
	log.Debug().Str("proc", "flow").Int("timeout_min", timeoutMin).Msg("config")
	return &FlowProcessor{
		m:       make(map[packets.FiveTuple]*Entry, 1000),
		Timeout: time.Duration(timeoutMin) * time.Minute,
	}
}

func (f *FlowProcessor) Name() string {
	return "flow"
}

func (f *FlowProcessor) Subs() []eventbus.Topic {
	return []eventbus.Topic{"packet", "flow.attach_telemetry"}
}

func (f *FlowProcessor) Pubs() []eventbus.Topic {
	return []eventbus.Topic{"flow.created", "flow.expired"}
}

func (f *FlowProcessor) EventHandler(topic eventbus.Topic, event interface{}) {
	switch topic {
	case "packet":
		p := event.(packets.Packet)
		k := p.GetKey()
		entry, exists := f.m[k]
		if !exists {
			f.Insert(p)
		} else {
			f.Update(p, entry)
		}
		f.expireEntries(p.Timestamp)
	case "flow.attach_telemetry":
		at := event.(EventAttachPerFlowTelemetry)
		entry, exists := f.m[at.Header]
		if !exists {
			log.Warn().Str("header", fmt.Sprint(at.Header)).
				Str("telemetry", fmt.Sprint(at.TelemetryFunctions)).
				Msg("entry doesn't exist")
			return
		}
		for _, tf := range at.TelemetryFunctions {
			_, exists := entry.TFS[tf.Name()]
			if exists {
				log.Warn().Str("header", fmt.Sprint(at.Header)).
					Str("telemetry", fmt.Sprint(at.TelemetryFunctions)).
					Msg("duplicate telemetry!")
				continue
			}
			entry.TFS[tf.Name()] = tf
		}
	}
}

type FlowCreatedEvent struct {
	CreatedTS time.Time
	Header    packets.FiveTuple
}

type FlowExpiredEvent struct {
	FirstPacketTS time.Time
	LastPacketTS  time.Time
	ExpiredTS     time.Time
	Header        packets.FiveTuple
	DownBytes     uint
	UpBytes       uint
	DownPackets   uint
	UpPackets     uint
}

type Entry struct {
	Header    packets.FiveTuple
	CreatedTS time.Time
	UpdatedTS time.Time

	Prev *Entry
	Next *Entry

	// Counters
	DownBytes   uint
	UpBytes     uint
	DownPackets uint
	UpPackets   uint

	TFS map[string]telemetry.Telemetry
}

func (entry *Entry) UpdateOnPacket(p packets.Packet) {
	entry.UpdatedTS = p.Timestamp
	if p.IsOutbound {
		entry.UpPackets++
		entry.UpBytes += p.TotalLen
	} else {
		entry.DownPackets++
		entry.DownBytes += p.TotalLen
	}

	for _, tf := range entry.TFS {
		tf.OnFlowPacket(p)
	}
}

func (f *FlowProcessor) Insert(p packets.Packet) {
	// Create new entry
	prevPtr := f.latest
	key := p.GetKey()
	entry := &Entry{
		Header:    key,
		CreatedTS: p.Timestamp,
		Prev:      prevPtr,
		Next:      nil,
		TFS:       make(map[string]telemetry.Telemetry),
	}

	// Insert into map
	f.MakeEntrylatest(entry)
	f.m[key] = entry
	f.nEntries++

	// Publish the event -- may have downstream deps and
	// can add telemetry functions as a result
	f.Publish("flow.created", FlowCreatedEvent{
		CreatedTS: p.Timestamp,
		Header:    key,
	})

	// Init telemetry functions
	for _, tf := range entry.TFS {
		tf.Init()
	}

	entry.UpdateOnPacket(p)
}

// MakeEntrylatest sets appropriate pointers to make the inserted entry to latest
func (f *FlowProcessor) MakeEntrylatest(entry *Entry) {
	if f.oldest == nil {
		f.oldest = entry
		f.latest = entry
	} else {
		// next of latest points to this
		f.latest.Next = entry
		// latest always points to new value
		f.latest = entry
	}
}

func (f *FlowProcessor) Update(pd packets.Packet, entry *Entry) {
	entry.UpdateOnPacket(pd)
	f.getEntryToTop(entry)
}

func (f *FlowProcessor) getEntryToTop(entry *Entry) {
	if f.latest == entry {
		// already top entry
		return
	}

	if f.oldest != entry {
		entry.Next.Prev = entry.Prev
		entry.Prev.Next = entry.Next

		entry.Prev = f.latest
		entry.Next = nil
		f.latest.Next = entry
		f.latest = entry

	} else {

		f.oldest = entry.Next
		entry.Next.Prev = nil

		entry.Prev = f.latest
		entry.Next = nil
		f.latest.Next = entry
		f.latest = entry

	}
}

func (f *FlowProcessor) expireEntries(now time.Time) {
	if f.oldest == nil {
		// log.Println("Map is already empty! oldest pointer nil!")
		return
	}
	for now.Sub(f.oldest.UpdatedTS) >= f.Timeout {
		entry := f.oldest
		f.BeforeExpire(entry, now)
		delete(f.m, entry.Header)
		f.nExpired++
		f.oldest = entry.Next
		if entry.Next == nil {
			f.latest = nil
			return
		}
		entry.Next.Prev = nil
	}
}

func (f *FlowProcessor) BeforeExpire(entry *Entry, now time.Time) {
	// Teardown telemetry functions
	for _, tf := range entry.TFS {
		tf.Teardown()
	}

	f.Publish("flow.expired", FlowExpiredEvent{
		FirstPacketTS: entry.CreatedTS,
		LastPacketTS:  entry.UpdatedTS,
		ExpiredTS:     now,
		Header:        entry.Header,
		DownBytes:     entry.DownBytes,
		UpBytes:       entry.UpBytes,
		DownPackets:   entry.DownPackets,
		UpPackets:     entry.UpPackets,
	})
}