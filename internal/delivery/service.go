package delivery

import (
	"fmt"
	"os"
	"path/filepath"
	"sort"
	"strings"
	"sync"
	"time"

	"github.com/google/uuid"

	"orbitlink/internal/audit"
	"orbitlink/internal/pass"
	"orbitlink/internal/receiver"
	"orbitlink/internal/recorder"
	"orbitlink/internal/store"
)

// Service assembles immutable, revision-bound delivery reports for passes.
type Service struct {
	mu       sync.RWMutex
	paths    store.Paths
	passes   *pass.Service
	attempts *receiver.AttemptDispatcher
	recorder *recorder.Manager
	audit    *audit.Trail
	reports  map[string]Report
}

func NewService(paths store.Paths, passes *pass.Service, attempts *receiver.AttemptDispatcher, manager *recorder.Manager, trail *audit.Trail) *Service {
	return &Service{paths: paths, passes: passes, attempts: attempts, recorder: manager, audit: trail, reports: make(map[string]Report)}
}

func reportName(passID string, revision int64) string {
	return fmt.Sprintf("%s-r%d", passID, revision)
}

// Generate builds the report for the pass's current revision. A report that
// already exists for that revision is returned unchanged and never rewritten.
func (s *Service) Generate(passID string) (Report, bool, error) {
	value, found := s.passes.Get(passID)
	if !found {
		return Report{}, false, fmt.Errorf("pass %s not found", passID)
	}
	name := reportName(passID, value.Window.Revision)
	s.mu.RLock()
	existing, ok := s.reports[name]
	s.mu.RUnlock()
	if ok {
		return existing, false, nil
	}
	var stored Report
	foundOnDisk, err := store.ReadJSON(s.paths.Delivery(name), &stored)
	if err != nil {
		return Report{}, false, err
	}
	if foundOnDisk {
		s.mu.Lock()
		s.reports[name] = stored
		s.mu.Unlock()
		return stored, false, nil
	}
	report, err := s.build(value)
	if err != nil {
		return Report{}, false, err
	}
	if err := store.WriteJSON(s.paths.Delivery(name), report); err != nil {
		return Report{}, false, err
	}
	s.mu.Lock()
	s.reports[name] = report
	s.mu.Unlock()
	_, _ = s.audit.Record(audit.Event{Component: "delivery", Action: "generated", Subject: passID, Fields: map[string]any{"revision": report.Revision, "report_id": report.ID, "complete": report.Complete, "gaps": len(report.Gaps), "checksum": report.Checksum}})
	return report, true, nil
}

// Download returns a stored report after verifying its checksum. It is a pure
// read: no pass state, recording state or audit trail is modified.
func (s *Service) Download(passID string, revision int64) (Report, bool, error) {
	if revision <= 0 {
		value, found := s.passes.Get(passID)
		if !found {
			return Report{}, false, fmt.Errorf("pass %s not found", passID)
		}
		revision = value.Window.Revision
	}
	name := reportName(passID, revision)
	var report Report
	found, err := store.ReadJSON(s.paths.Delivery(name), &report)
	if err != nil {
		return Report{}, false, err
	}
	if !found {
		return Report{}, false, fmt.Errorf("delivery report for pass %s revision %d has not been generated", passID, revision)
	}
	if report.PassID != passID || report.Revision != revision {
		return Report{}, false, fmt.Errorf("delivery report %s does not match its binding", name)
	}
	if report.ComputeChecksum() != report.Checksum {
		return Report{}, false, fmt.Errorf("delivery report for pass %s revision %d fails integrity verification", passID, revision)
	}
	s.mu.Lock()
	s.reports[name] = report
	s.mu.Unlock()
	return report, true, nil
}

// List returns summaries of every stored report for one pass.
func (s *Service) List(passID string) ([]Summary, error) {
	entries, err := os.ReadDir(filepath.Join(s.paths.Root, "deliveries"))
	if os.IsNotExist(err) {
		return []Summary{}, nil
	}
	if err != nil {
		return nil, fmt.Errorf("list deliveries: %w", err)
	}
	summaries := make([]Summary, 0, len(entries))
	for _, entry := range entries {
		if entry.IsDir() || !strings.HasSuffix(entry.Name(), ".json") {
			continue
		}
		var report Report
		found, err := store.ReadJSON(s.paths.Delivery(strings.TrimSuffix(entry.Name(), ".json")), &report)
		if err != nil {
			return nil, err
		}
		if found && report.PassID == passID {
			summaries = append(summaries, report.Summarize())
		}
	}
	sort.Slice(summaries, func(i, j int) bool { return summaries[i].Revision < summaries[j].Revision })
	return summaries, nil
}

func (s *Service) build(value pass.Pass) (Report, error) {
	report := Report{
		ID: uuid.NewString(), PassID: value.ID, Revision: value.Window.Revision, GeneratedAt: time.Now().UTC(),
		Pass: PassSummary{
			ID: value.ID, SatelliteID: value.SatelliteID, AntennaID: value.AntennaID, Phase: value.Phase,
			AOS: value.Window.AOS, LOS: value.Window.LOS, FailureReason: value.FailureReason,
		},
		CRCIndex: []CRCEntry{}, RFPlans: []RFPlanSummary{}, AuditEvents: []audit.Event{}, Gaps: []Gap{},
	}
	report.Receiver = s.receiverSummary(value)
	report.Decoder = s.decoderSummary(value)
	segment, found := s.segmentFor(value)
	if found {
		recording, scan, err := s.recordingSummary(segment)
		if err != nil {
			return Report{}, err
		}
		report.Recording = recording
		report.CRCIndex = scan.entries
		report.Gaps = append(report.Gaps, scan.gaps...)
	}
	report.RFPlans = s.rfPlans(value)
	report.AuditEvents = s.passEvents(value, segment, found)
	report.Gaps = append(report.Gaps, report.gaps(value, segment, found)...)
	report.Complete = len(report.Gaps) == 0
	report.Checksum = report.ComputeChecksum()
	return report, nil
}

func (s *Service) receiverSummary(value pass.Pass) ReceiverSummary {
	summary := ReceiverSummary{Attempts: []AttemptSummary{}, CurrentAttemptID: value.CurrentAttemptID}
	for _, attempt := range s.attempts.List() {
		if attempt.PassID != value.ID {
			continue
		}
		summary.Attempts = append(summary.Attempts, AttemptSummary{
			ID: attempt.ID, ChainID: attempt.ChainID, Number: attempt.Number, Status: attempt.Status,
			Epoch: attempt.Epoch, ErrorCode: attempt.ErrorCode, StartedAt: attempt.StartedAt, FinishedAt: attempt.FinishedAt,
		})
		switch attempt.Status {
		case receiver.AttemptLocked:
			summary.Locked++
		case receiver.AttemptFailed:
			summary.Failed++
		}
	}
	sort.Slice(summary.Attempts, func(i, j int) bool { return summary.Attempts[i].Number < summary.Attempts[j].Number })
	return summary
}

func (s *Service) decoderSummary(value pass.Pass) DecoderSummary {
	summary := DecoderSummary{CurrentEpoch: value.DecoderEpoch, Epochs: []EpochSummary{}}
	for _, event := range s.audit.List(audit.Query{Component: "decoder", Subject: value.ID}) {
		if event.Action != "epoch.started" {
			continue
		}
		epoch := EpochSummary{Epoch: numberField(event.Fields, "epoch"), AttemptID: stringField(event.Fields, "attempt_id"), DiscardedSymbols: int(numberField(event.Fields, "discarded_symbols"))}
		summary.Epochs = append(summary.Epochs, epoch)
		summary.LostSymbols += epoch.DiscardedSymbols
	}
	sort.Slice(summary.Epochs, func(i, j int) bool { return summary.Epochs[i].Epoch < summary.Epochs[j].Epoch })
	return summary
}

func (s *Service) segmentFor(value pass.Pass) (recorder.Segment, bool) {
	segments := s.recorder.List()
	if value.RecordingSegmentID != "" {
		for _, segment := range segments {
			if segment.ID == value.RecordingSegmentID {
				return segment, true
			}
		}
	}
	latest := recorder.Segment{}
	for _, segment := range segments {
		if segment.PassID == value.ID && (latest.ID == "" || segment.StartedAt.After(latest.StartedAt)) {
			latest = segment
		}
	}
	return latest, latest.ID != ""
}

func (s *Service) recordingSummary(segment recorder.Segment) (*RecordingSummary, frameScan, error) {
	scan, err := scanFrames(s.paths.Recording(segment.ID))
	if err != nil {
		return nil, frameScan{}, err
	}
	return &RecordingSummary{
		SegmentID: segment.ID, Status: segment.Status, OwnerStation: segment.OwnerStation, OwnerGeneration: segment.OwnerGeneration,
		FramesWritten: segment.FramesWritten, FramesBuffered: segment.FramesBuffered, StartedAt: segment.StartedAt,
		SealedAt: segment.SealedAt, SealReason: segment.SealReason, FileBytes: scan.bytes, PayloadSHA256: scan.checksum,
	}, scan, nil
}

func (s *Service) rfPlans(value pass.Pass) []RFPlanSummary {
	plans := []RFPlanSummary{}
	for _, event := range s.audit.List(audit.Query{Component: "rf"}) {
		if event.Action != "plan.applied" || stringField(event.Fields, "pass_id") != value.ID {
			continue
		}
		plans = append(plans, RFPlanSummary{
			ChainID: event.Subject, CenterHz: numberField(event.Fields, "center_hz"),
			DopplerHz: numberField(event.Fields, "doppler_hz"), AppliedAt: event.At,
		})
	}
	sort.Slice(plans, func(i, j int) bool {
		if plans[i].ChainID != plans[j].ChainID {
			return plans[i].ChainID < plans[j].ChainID
		}
		return plans[i].AppliedAt.Before(plans[j].AppliedAt)
	})
	return plans
}

// passEvents merges the audit trail for the pass, its recording segment and
// its receiver attempts into one ordered timeline.
func (s *Service) passEvents(value pass.Pass, segment recorder.Segment, hasSegment bool) []audit.Event {
	subjects := []string{value.ID}
	if hasSegment {
		subjects = append(subjects, segment.ID)
	}
	for _, attempt := range s.attempts.List() {
		if attempt.PassID == value.ID {
			subjects = append(subjects, attempt.ID)
		}
	}
	seen := make(map[string]bool)
	events := []audit.Event{}
	for _, subject := range subjects {
		for _, event := range s.audit.List(audit.Query{Subject: subject}) {
			if seen[event.ID] {
				continue
			}
			seen[event.ID] = true
			events = append(events, event)
		}
	}
	sort.Slice(events, func(i, j int) bool {
		if !events[i].At.Equal(events[j].At) {
			return events[i].At.Before(events[j].At)
		}
		return events[i].ID < events[j].ID
	})
	return events
}

// gaps annotates every known hole in the delivered data.
func (r Report) gaps(value pass.Pass, segment recorder.Segment, hasSegment bool) []Gap {
	gaps := []Gap{}
	if value.Phase != pass.Completed && value.Phase != pass.Sealed {
		detail := fmt.Sprintf("pass is in phase %s", value.Phase)
		if value.FailureReason != "" {
			detail += ": " + value.FailureReason
		}
		gaps = append(gaps, Gap{Code: "pass.not-completed", Detail: detail})
	}
	for _, attempt := range r.Receiver.Attempts {
		if attempt.Status == receiver.AttemptFailed {
			gaps = append(gaps, Gap{Code: "acquisition.failed", Detail: fmt.Sprintf("attempt %d on chain %s failed: %s", attempt.Number, attempt.ChainID, attempt.ErrorCode)})
		}
	}
	if r.Decoder.LostSymbols > 0 {
		gaps = append(gaps, Gap{Code: "decoder.symbols-lost", Detail: fmt.Sprintf("%d symbols discarded across epoch resets", r.Decoder.LostSymbols)})
	}
	if !hasSegment {
		gaps = append(gaps, Gap{Code: "recording.missing", Detail: "pass has no recording segment"})
	} else if segment.FramesBuffered > 0 {
		gaps = append(gaps, Gap{Code: "recording.frames-buffered", Detail: fmt.Sprintf("%d frames were never drained to storage", segment.FramesBuffered)})
	}
	planned := make(map[string]bool, len(r.RFPlans))
	for _, plan := range r.RFPlans {
		planned[plan.ChainID] = true
	}
	for _, chain := range value.RFChains {
		if !planned[chain] {
			gaps = append(gaps, Gap{Code: "rf.plan-missing", Detail: fmt.Sprintf("RF chain %s has no applied plan for this pass", chain)})
		}
	}
	return gaps
}

func stringField(fields map[string]any, key string) string {
	if value, ok := fields[key].(string); ok {
		return value
	}
	return ""
}

func numberField(fields map[string]any, key string) int64 {
	switch value := fields[key].(type) {
	case int:
		return int64(value)
	case int64:
		return value
	case float64:
		return int64(value)
	}
	return 0
}
