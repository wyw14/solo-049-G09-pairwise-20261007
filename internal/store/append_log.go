package store

import (
	"bufio"
	"encoding/json"
	"fmt"
	"os"
	"path/filepath"
	"sync"
	"time"
)

type Event struct {
	ID        string         `json:"id"`
	Stream    string         `json:"stream"`
	Kind      string         `json:"kind"`
	At        time.Time      `json:"at"`
	Severity  string         `json:"severity,omitempty"`
	Subject   string         `json:"subject,omitempty"`
	Fields    map[string]any `json:"fields,omitempty"`
	Operation string         `json:"operation,omitempty"`
}

// AppendLog serializes each event stream and fsyncs accepted control events.
type AppendLog struct {
	paths Paths
	mu    sync.Mutex
}

func NewAppendLog(paths Paths) *AppendLog {
	return &AppendLog{paths: paths}
}

func (l *AppendLog) Append(event Event) error {
	l.mu.Lock()
	defer l.mu.Unlock()
	path := l.paths.Events(event.Stream)
	if err := os.MkdirAll(filepath.Dir(path), 0o755); err != nil {
		return fmt.Errorf("create event directory: %w", err)
	}
	file, err := os.OpenFile(path, os.O_CREATE|os.O_APPEND|os.O_WRONLY, 0o644)
	if err != nil {
		return fmt.Errorf("open event stream: %w", err)
	}
	encoded, err := json.Marshal(event)
	if err == nil {
		_, err = file.Write(append(encoded, '\n'))
	}
	if err == nil {
		err = file.Sync()
	}
	closeErr := file.Close()
	if err != nil {
		return fmt.Errorf("append event: %w", err)
	}
	if closeErr != nil {
		return fmt.Errorf("close event stream: %w", closeErr)
	}
	return nil
}

func (l *AppendLog) Read(stream string, limit int) ([]Event, error) {
	l.mu.Lock()
	defer l.mu.Unlock()
	file, err := os.Open(l.paths.Events(stream))
	if os.IsNotExist(err) {
		return []Event{}, nil
	}
	if err != nil {
		return nil, fmt.Errorf("open event stream: %w", err)
	}
	defer file.Close()
	var events []Event
	scanner := bufio.NewScanner(file)
	buffer := make([]byte, 64*1024)
	scanner.Buffer(buffer, 1024*1024)
	for scanner.Scan() {
		var event Event
		if err := json.Unmarshal(scanner.Bytes(), &event); err != nil {
			return nil, fmt.Errorf("decode event: %w", err)
		}
		events = append(events, event)
	}
	if err := scanner.Err(); err != nil {
		return nil, fmt.Errorf("scan events: %w", err)
	}
	if limit > 0 && len(events) > limit {
		events = events[len(events)-limit:]
	}
	return events, nil
}
