package delivery

import (
	"fmt"
	"os"
	"path/filepath"
	"sort"
	"strings"
	"sync"

	"github.com/google/uuid"

	"orbitlink/internal/audit"
	passsvc "orbitlink/internal/pass"
	"orbitlink/internal/receiver"
	"orbitlink/internal/recorder"
	"orbitlink/internal/rf"
	"orbitlink/internal/store"
)

// DecoderSnapshotSource provides the live, read-only decoder state for a pass.
// It is intentionally narrow so the delivery service never touches the decoder.
type DecoderSnapshotSource interface {
	DecoderSnapshot(passID string) (attemptID string, epoch int64, lostSymbols int, found bool)
}

type Service struct {
	mu        sync.RWMutex
	paths     store.Paths
	passes    *passsvc.Service
	attempts  *receiver.AttemptDispatcher
	recorders *recorder.Manager
	rf        *rf.Controller
	events    *store.AppendLog
	audit     *audit.Trail
	decoders  DecoderSnapshotSource
	reports   map[string]Report
}

func NewService(paths store.Paths, passes *passsvc.Service, attempts *receiver.AttemptDispatcher,
	recorders *recorder.Manager, rfController *rf.Controller, events *store.AppendLog,
	trail *audit.Trail, decoders DecoderSnapshotSource) (*Service, error) {
	service := &Service{
		paths: paths, passes: passes, attempts: attempts, recorders: recorders, rf: rfController,
		events: events, audit: trail, decoders: decoders, reports: make(map[string]Report),
	}
	if err := service.load(); err != nil {
		return nil, err
	}
	return service, nil
}

func (s *Service) load() error {
	entries, err := os.ReadDir(s.paths.DeliveryDir())
	if os.IsNotExist(err) {
		return nil
	}
	if err != nil {
		return fmt.Errorf("read delivery directory: %w", err)
	}
	for _, entry := range entries {
		if entry.IsDir() || !strings.HasSuffix(entry.Name(), ".json") {
			continue
		}
		path := filepath.Join(s.paths.DeliveryDir(), entry.Name())
		var report Report
		found, err := store.ReadJSON(path, &report)
		if err != nil {
			return err
		}
		if found && report.PassID != "" {
			s.reports[report.PassID] = report
		}
	}
	return nil
}

// Generate seals the immutable report for a pass. A repeat request for an
// already-delivered pass never rebuilds state: it verifies the stored report.
func (s *Service) Generate(passID string) (Verification, error) {
	value, found := s.passes.Get(passID)
	if !found {
		return Verification{}, fmt.Errorf("pass %s not found", passID)
	}
	if !terminal(value.Phase) {
		return Verification{}, fmt.Errorf("pass %s cannot be delivered from phase %s", passID, value.Phase)
	}

	s.mu.Lock()
	if existing, ok := s.reports[passID]; ok {
		s.mu.Unlock()
		return s.verify(existing)
	}

	input, err := s.gather(value)
	if err != nil {
		s.mu.Unlock()
		return Verification{}, err
	}
	report := buildReport(input)
	report.ID = uuid.NewString()
	if err := report.seal(); err != nil {
		s.mu.Unlock()
		return Verification{}, err
	}

	path := s.paths.Delivery(passID)
	if err := store.WriteJSON(path, report); err != nil {
		s.mu.Unlock()
		return Verification{}, err
	}
	// Freeze the artifact: readers verify, nobody rewrites this revision.
	if err := os.Chmod(path, 0o444); err != nil {
		s.mu.Unlock()
		return Verification{}, fmt.Errorf("freeze delivery report: %w", err)
	}
	s.reports[passID] = report
	s.mu.Unlock()

	_, _ = s.audit.Record(audit.Event{
		Component: "delivery", Action: "report.sealed", Subject: passID,
		Fields: map[string]any{
			"report_id": report.ID, "revision": report.Revision, "status": string(report.Status),
			"gaps": len(report.Gaps), "sha256": report.SHA256,
		},
	})
	return Verification{Report: report, Intact: true, Reused: false, RevisionCurrent: true, CurrentRevision: report.Revision}, nil
}

// Download re-verifies the sealed report without changing any task state.
func (s *Service) Download(passID string) (Verification, error) {
	s.mu.RLock()
	report, ok := s.reports[passID]
	s.mu.RUnlock()
	if !ok {
		return Verification{}, fmt.Errorf("no delivery report for pass %s", passID)
	}
	return s.verify(report)
}

// verify always reads the artifact back from disk so tampering is detected.
func (s *Service) verify(cached Report) (Verification, error) {
	var stored Report
	found, err := store.ReadJSON(s.paths.Delivery(cached.PassID), &stored)
	if err != nil {
		return Verification{}, err
	}
	if !found {
		return Verification{}, fmt.Errorf("delivery report file for pass %s is missing", cached.PassID)
	}
	intact, err := stored.VerifyDigest()
	if err != nil {
		return Verification{}, err
	}
	if !intact {
		_, _ = s.audit.Record(audit.Event{Component: "delivery", Action: "report.tampered", Subject: cached.PassID, Severity: audit.Critical, Fields: map[string]any{"report_id": stored.ID, "revision": stored.Revision}})
		return Verification{Report: stored, Intact: false}, fmt.Errorf("delivery report for pass %s failed integrity verification", cached.PassID)
	}
	current, found := s.passes.Get(cached.PassID)
	currentRevision := stored.Revision
	if found {
		currentRevision = current.Window.Revision
	}
	return Verification{
		Report: stored, Intact: true, Reused: true,
		RevisionCurrent: found && current.Window.Revision == stored.Revision,
		CurrentRevision: currentRevision,
	}, nil
}

func (s *Service) Get(passID string) (Report, bool) {
	s.mu.RLock()
	defer s.mu.RUnlock()
	report, found := s.reports[passID]
	return report, found
}

func (s *Service) List() []Report {
	s.mu.RLock()
	defer s.mu.RUnlock()
	reports := make([]Report, 0, len(s.reports))
	for _, report := range s.reports {
		reports = append(reports, report)
	}
	sort.Slice(reports, func(i, j int) bool { return reports[i].GeneratedAt.Before(reports[j].GeneratedAt) })
	return reports
}

func (s *Service) gather(value passsvc.Pass) (Input, error) {
	input := Input{Pass: value, Attempts: s.attempts.List(), RFStates: s.rf.List()}

	if s.decoders != nil {
		if attemptID, epoch, lostSymbols, found := s.decoders.DecoderSnapshot(value.ID); found {
			input.DecoderAttempt, input.DecoderEpoch, input.LostSymbols = attemptID, epoch, lostSymbols
		}
	}

	if value.RecordingSegmentID != "" {
		if segment, found := s.recordersSegment(value.RecordingSegmentID); found {
			input.Segment, input.SegmentFound = segment, true
			index, present, err := s.recorders.FrameIndex(segment.ID)
			if err != nil {
				return Input{}, err
			}
			input.Index, input.IndexPresent = index, present
			input.RecordingPath = s.paths.Recording(segment.ID)
		}
	}

	events, err := s.events.Read("audit", 0)
	if err != nil {
		return Input{}, fmt.Errorf("read audit trail for delivery: %w", err)
	}
	for _, event := range events {
		converted := convertEvent(event)
		if attributableToPass(converted, value.ID, value.RecordingSegmentID) {
			input.AuditEvents = append(input.AuditEvents, converted)
		}
	}
	return input, nil
}

func (s *Service) recordersSegment(segmentID string) (recorder.Segment, bool) {
	for _, segment := range s.recorders.List() {
		if segment.ID == segmentID {
			return segment, true
		}
	}
	return recorder.Segment{}, false
}

func convertEvent(event store.Event) audit.Event {
	component, action := event.Kind, ""
	if index := strings.Index(event.Kind, "."); index >= 0 {
		component, action = event.Kind[:index], event.Kind[index+1:]
	}
	severity := audit.Severity(event.Severity)
	if severity == "" {
		severity = audit.Info
	}
	return audit.Event{
		ID: event.ID, At: event.At, Component: component, Action: action, Severity: severity,
		Operation: event.Operation, Subject: event.Subject, Fields: event.Fields,
	}
}

func terminal(phase passsvc.Phase) bool {
	switch phase {
	case passsvc.Completed, passsvc.Sealed, passsvc.Failed, passsvc.Canceled:
		return true
	default:
		return false
	}
}
