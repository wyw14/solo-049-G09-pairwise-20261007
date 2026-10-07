package audit

import (
	"fmt"
	"sync"
	"time"

	"github.com/google/uuid"

	"orbitlink/internal/store"
)

type Trail struct {
	log *store.AppendLog
	mu  sync.RWMutex
	all []Event
}

func NewTrail(log *store.AppendLog) *Trail {
	return &Trail{log: log, all: make([]Event, 0, 128)}
}

func (t *Trail) Record(event Event) (Event, error) {
	if event.Component == "" || event.Action == "" {
		return Event{}, fmt.Errorf("audit component and action are required")
	}
	if event.ID == "" {
		event.ID = uuid.NewString()
	}
	if event.At.IsZero() {
		event.At = time.Now().UTC()
	}
	if event.Severity == "" {
		event.Severity = Info
	}
	if err := t.log.Append(store.Event{
		ID: event.ID, Stream: "audit", Kind: event.Component + "." + event.Action,
		At: event.At, Severity: string(event.Severity), Subject: event.Subject,
		Fields: event.Fields, Operation: event.Operation,
	}); err != nil {
		return Event{}, err
	}
	t.mu.Lock()
	t.all = append(t.all, event)
	t.mu.Unlock()
	return event, nil
}

func (t *Trail) List(query Query) []Event {
	t.mu.RLock()
	defer t.mu.RUnlock()
	filtered := make([]Event, 0, len(t.all))
	for _, event := range t.all {
		if query.Component != "" && event.Component != query.Component {
			continue
		}
		if query.Subject != "" && event.Subject != query.Subject {
			continue
		}
		filtered = append(filtered, event)
	}
	if query.Limit > 0 && len(filtered) > query.Limit {
		filtered = filtered[len(filtered)-query.Limit:]
	}
	return append([]Event(nil), filtered...)
}
