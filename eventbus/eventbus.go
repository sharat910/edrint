package eventbus

import "sync"

type Topic string

type EventBus struct {
	topics map[Topic][]EventHandler
	lock   sync.RWMutex
}

func New() *EventBus {
	return &EventBus{
		topics: make(map[Topic][]EventHandler),
	}
}

type EventHandler func(topic Topic, event interface{})

func (eb *EventBus) Publish(topic Topic, event interface{}) {
	eb.lock.RLock()
	defer eb.lock.RUnlock()
	for _, handler := range eb.topics[topic] {
		handler(topic, event)
	}
}

func (eb *EventBus) Subscribe(topic Topic, eh EventHandler) {
	eb.lock.Lock()
	defer eb.lock.Unlock()
	eb.topics[topic] = append(eb.topics[topic], eh)
}

func (eb *EventBus) GetSubscriptions() map[Topic]int {
	eb.lock.RLock()
	defer eb.lock.RUnlock()
	m := make(map[Topic]int, len(eb.topics))
	for topic, handlers := range eb.topics {
		m[topic] = len(handlers)
	}
	return m
}
