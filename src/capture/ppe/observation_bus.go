package ppe

import "sync"

type ObservationSink interface {
	Observe(PassiveObservation)
}

type ObservationBus struct {
	mu     sync.RWMutex
	nextID uint64
	sinks  map[uint64]ObservationSink
}

func NewObservationBus() *ObservationBus {
	return &ObservationBus{sinks: make(map[uint64]ObservationSink)}
}

func (b *ObservationBus) Observe(observation PassiveObservation) {
	if b == nil {
		return
	}
	b.mu.RLock()
	sinks := make([]ObservationSink, 0, len(b.sinks))
	for _, sink := range b.sinks {
		sinks = append(sinks, sink)
	}
	b.mu.RUnlock()
	for _, sink := range sinks {
		if sink != nil {
			sink.Observe(observation)
		}
	}
}

func (b *ObservationBus) Subscribe(sink ObservationSink) func() {
	if b == nil || sink == nil {
		return func() {}
	}
	b.mu.Lock()
	b.nextID++
	id := b.nextID
	b.sinks[id] = sink
	b.mu.Unlock()
	var once sync.Once
	return func() {
		once.Do(func() {
			b.mu.Lock()
			delete(b.sinks, id)
			b.mu.Unlock()
		})
	}
}
