package receiver

import (
	"fmt"
	"sync"

	"orbitlink/internal/decoder"
)

type Session struct {
	mu      sync.Mutex
	passID  string
	current string
	locked  bool
	decoder *decoder.Session
}

func NewSession(passID string, decoderSession *decoder.Session) *Session {
	return &Session{passID: passID, decoder: decoderSession}
}

func (s *Session) OnLock(attemptID string) (int64, error) {
	s.mu.Lock()
	defer s.mu.Unlock()
	if attemptID == "" {
		return 0, fmt.Errorf("lock attempt is required")
	}
	epoch, err := s.decoder.BeginEpoch(attemptID)
	if err != nil {
		return 0, err
	}
	s.current = attemptID
	s.locked = true
	return epoch, nil
}

func (s *Session) OnCarrierLoss(attemptID string) error {
	s.mu.Lock()
	defer s.mu.Unlock()
	if s.current != attemptID {
		return nil
	}
	s.locked = false
	return nil
}

func (s *Session) Feed(attemptID string, symbols []byte) (int, error) {
	s.mu.Lock()
	active := s.current == attemptID && s.locked
	s.mu.Unlock()
	if !active {
		return 0, fmt.Errorf("receiver attempt is not locked")
	}
	return s.decoder.Feed(attemptID, symbols)
}

func (s *Session) Status() (attemptID string, locked bool) {
	s.mu.Lock()
	defer s.mu.Unlock()
	return s.current, s.locked
}

// DecoderSnapshot exposes the decoder epoch state without changing anything.
func (s *Session) DecoderSnapshot() (attemptID string, epoch int64, lostSymbols int) {
	return s.decoder.Snapshot()
}
