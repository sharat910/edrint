package edrint

import (
	"errors"
	"fmt"

	"github.com/rs/zerolog/log"
	"github.com/sharat910/edrint/events"
	"github.com/sharat910/edrint/processor"
)

type Manager struct {
	eb         *events.EventBus
	processors []processor.Processor
	pMap       map[string]struct{}
}

func New() Manager {
	return Manager{
		eb:         events.New(),
		processors: nil,
		pMap:       make(map[string]struct{}),
	}
}

func (m *Manager) RegisterProc(p processor.Processor) {
	if _, ok := m.pMap[p.Name()]; ok {
		log.Fatal().Str("proc", p.Name()).Msg("processor already exists")
	}
	m.pMap[p.Name()] = struct{}{}
	m.processors = append(m.processors, p)
}

func (m *Manager) InitProcessors() error {
	if len(m.processors) == 0 {
		return errors.New("no processors registered")
	}

	if err := m.SanityCheck(); err != nil {
		return err
	}

	for _, proc := range m.processors {

		// Initialize the processor
		proc.Init()

		// Subscribe to topics by passing proc's event handlers
		for _, topic := range proc.Subs() {
			log.Info().Str("proc", proc.Name()).Str("topic", string(topic)).Msg("subscription")
			m.eb.Subscribe(topic, proc.EventHandler)
		}

		// Pass events to procs that publish
		if len(proc.Pubs()) > 0 {
			proc.SetPubFunc(m.eb.Publish)
		}

	}
	return nil
}

func (m *Manager) Run(c ParserConfig) error {
	// Start processing packets
	if err := PacketParser(c, m.eb.Publish); err != nil {
		return err
	}

	for _, proc := range m.processors {
		proc.Teardown()
	}

	return nil
}

func (m *Manager) SanityCheck() error {
	pubs := make(map[events.Topic]struct{})
	pubs[events.PACKET] = struct{}{}
	for _, proc := range m.processors {
		for _, pub := range proc.Pubs() {
			pubs[pub] = struct{}{}
		}
	}
	for _, proc := range m.processors {
		for _, sub := range proc.Subs() {
			if _, ok := pubs[sub]; !ok {
				return fmt.Errorf("proc: %s wants %s: no publishers for %s", proc.Name(), sub, sub)
			}
		}
	}
	return nil
}
