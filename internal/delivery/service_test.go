package delivery

import (
	"context"
	"os"
	"testing"
	"time"

	"orbitlink/internal/audit"
	passsvc "orbitlink/internal/pass"
	"orbitlink/internal/receiver"
	"orbitlink/internal/recorder"
	"orbitlink/internal/rf"
	"orbitlink/internal/store"
)

type decoderState struct {
	attempt string
	epoch   int64
	lost    int
}

type fakeDecoders map[string]decoderState

func (f fakeDecoders) DecoderSnapshot(passID string) (string, int64, int, bool) {
	state, ok := f[passID]
	return state.attempt, state.epoch, state.lost, ok
}

type harness struct {
	paths     store.Paths
	log       *store.AppendLog
	audit     *audit.Trail
	passes    *passsvc.Service
	attempts  *receiver.AttemptDispatcher
	recorders *recorder.Manager
	rf        *rf.Controller
	decoders  fakeDecoders
	service   *Service
}

func newHarness(t *testing.T) *harness {
	t.Helper()
	paths := store.NewPaths(t.TempDir())
	log := store.NewAppendLog(paths)
	trail := audit.NewTrail(log)
	rfController, err := rf.NewController(paths, trail, []string{"RF-01", "RF-02", "RF-03"})
	if err != nil {
		t.Fatal(err)
	}
	manager, err := recorder.NewManager(paths, trail)
	if err != nil {
		t.Fatal(err)
	}
	passes, err := passsvc.NewService(paths, manager, trail)
	if err != nil {
		t.Fatal(err)
	}
	dispatcher, err := receiver.NewAttemptDispatcher(paths, trail)
	if err != nil {
		t.Fatal(err)
	}
	dispatcher.SetSink(passes)
	decoders := fakeDecoders{}
	service, err := NewService(paths, passes, dispatcher, manager, rfController, log, trail, decoders)
	if err != nil {
		t.Fatal(err)
	}
	return &harness{paths: paths, log: log, audit: trail, passes: passes, attempts: dispatcher,
		recorders: manager, rf: rfController, decoders: decoders, service: service}
}

func (h *harness) createTrackingPass(t *testing.T, revision int64) passsvc.Pass {
	t.Helper()
	value, err := h.passes.Create(passsvc.CreateRequest{
		SatelliteID: "SAT-A12", AntennaID: "ANT-01",
		RFChains: []string{"RF-01", "RF-02"}, RequiredReceiverChains: []string{"RF-01", "RF-02"},
		AOS: time.Now().UTC(), LOS: time.Now().UTC().Add(8 * time.Minute),
		Revision: revision, OwnerStation: "north",
	})
	if err != nil {
		t.Fatal(err)
	}
	return value
}

func (h *harness) applyRFPlans(t *testing.T, passID string) {
	t.Helper()
	for _, chain := range []string{"RF-01", "RF-02"} {
		if _, err := h.rf.Apply(rf.Plan{PassID: passID, ChainID: chain, CenterHz: 2_245_000_000, DopplerHz: 12_000, Polarization: rf.RightCircular}); err != nil {
			t.Fatal(err)
		}
	}
}

// converge drives diversity to lock and leaves a sealed, completed pass.
func (h *harness) converge(t *testing.T, passID string, sequences ...uint64) {
	t.Helper()
	attempt, err := h.attempts.Begin(passID, "RF-01")
	if err != nil {
		t.Fatal(err)
	}
	if err := h.passes.BeginAcquisition(passID, attempt.ID); err != nil {
		t.Fatal(err)
	}
	results := []receiver.AcquisitionResult{
		{PassID: passID, AttemptID: attempt.ID, ChainID: "RF-01", Locked: true, Synced: true, Epoch: 7},
		{PassID: passID, AttemptID: attempt.ID, ChainID: "RF-02", Locked: true, Synced: true, Epoch: 7},
	}
	decision, err := h.passes.AcceptDiversity(passID, results)
	if err != nil || !decision.Ready {
		t.Fatalf("diversity did not converge: %#v %v", decision, err)
	}
	segment, found := h.recorders.ActiveForPass(passID)
	if !found {
		t.Fatal("tracking did not start a recorder")
	}
	h.decoders[passID] = decoderState{attempt: attempt.ID, epoch: decision.Epoch}
	for _, sequence := range sequences {
		if err := h.recorders.Buffer(segment.ID, recorder.Frame{Sequence: sequence, Epoch: decision.Epoch, Received: time.Now().UTC(), Payload: []byte("telemetry-frame")}); err != nil {
			t.Fatal(err)
		}
	}
	unlocker := receiver.NewUnlocker(h.audit)
	finalizer := passsvc.NewFinalizer(h.passes, h.recorders, unlocker, h.audit, 250*time.Millisecond)
	if _, err := finalizer.Finalize(context.Background(), passID, "RF-01"); err != nil {
		t.Fatal(err)
	}
}

func TestGenerateCompleteReportBindsRevisionAndAggregatesDomains(t *testing.T) {
	h := newHarness(t)
	value := h.createTrackingPass(t, 3)
	h.applyRFPlans(t, value.ID)
	h.converge(t, value.ID, 1, 2)

	verification, err := h.service.Generate(value.ID)
	if err != nil {
		t.Fatal(err)
	}
	if !verification.Intact || verification.Reused || !verification.RevisionCurrent {
		t.Fatalf("unexpected first verification: %+v", verification)
	}
	report := verification.Report
	if report.Status != Complete || len(report.Gaps) != 0 {
		t.Fatalf("expected complete report without gaps, got %s: %+v", report.Status, report.Gaps)
	}
	if report.Revision != 3 {
		t.Fatalf("report bound to revision %d, want 3", report.Revision)
	}
	if report.Decoder.Epoch != 7 || report.Receiver.Attempts == 0 {
		t.Fatalf("decoder/receiver not aggregated: %+v %+v", report.Decoder, report.Receiver)
	}
	if report.CRC.FramesIndexed != 2 || report.CRC.ValidFrames != 2 || report.CRC.CorruptFrames != 0 {
		t.Fatalf("CRC index wrong: %+v", report.CRC)
	}
	if report.Recording.FramesWritten != 2 || !report.Recording.FilePresent {
		t.Fatalf("recording summary wrong: %+v", report.Recording)
	}
	if len(report.RF.Chains) != 2 || report.Audit.Events == 0 || len(report.Artifacts) != 1 {
		t.Fatalf("rf/audit/artifacts wrong: %+v %+v %+v", report.RF, report.Audit, report.Artifacts)
	}

	info, err := os.Stat(h.paths.Delivery(value.ID))
	if err != nil {
		t.Fatal(err)
	}
	if perm := info.Mode().Perm(); perm != 0o444 {
		t.Fatalf("delivery report not frozen read-only: %o", perm)
	}
}

func TestRepeatGenerateAndDownloadOnlyVerifyWithoutStateChange(t *testing.T) {
	h := newHarness(t)
	value := h.createTrackingPass(t, 1)
	h.applyRFPlans(t, value.ID)
	h.converge(t, value.ID, 1, 2)

	first, err := h.service.Generate(value.ID)
	if err != nil {
		t.Fatal(err)
	}
	firstDigest := first.Report.SHA256

	passBefore, _ := h.passes.Get(value.ID)
	segmentBefore := h.recorders.List()[0]
	attemptsBefore := len(h.attempts.List())
	framesSizeBefore := fileSize(t, h.paths.Recording(segmentBefore.ID))

	second, err := h.service.Generate(value.ID)
	if err != nil {
		t.Fatal(err)
	}
	if !second.Reused || !second.Intact || second.Report.SHA256 != firstDigest || second.Report.ID != first.Report.ID {
		t.Fatalf("repeat generate rebuilt the report: %+v", second)
	}
	download, err := h.service.Download(value.ID)
	if err != nil {
		t.Fatal(err)
	}
	if !download.Reused || !download.Intact || download.Report.SHA256 != firstDigest {
		t.Fatalf("download did not verify the sealed report: %+v", download)
	}

	passAfter, _ := h.passes.Get(value.ID)
	segmentAfter := h.recorders.List()[0]
	if passAfter.Phase != passBefore.Phase || passAfter.UpdatedAt != passBefore.UpdatedAt {
		t.Fatalf("pass task state changed on repeat download")
	}
	if segmentAfter.Status != segmentBefore.Status || segmentAfter.FramesWritten != segmentBefore.FramesWritten {
		t.Fatalf("recording task state changed on repeat download")
	}
	if len(h.attempts.List()) != attemptsBefore || fileSize(t, h.paths.Recording(segmentBefore.ID)) != framesSizeBefore {
		t.Fatalf("attempts or recording file changed on repeat download")
	}
}

func TestReportSurvivesRestartAndFlagsRevisionDrift(t *testing.T) {
	h := newHarness(t)
	value := h.createTrackingPass(t, 1)
	h.applyRFPlans(t, value.ID)
	h.converge(t, value.ID, 1)
	if _, err := h.service.Generate(value.ID); err != nil {
		t.Fatal(err)
	}

	// A revised plan lands after sealing: rewrite the persisted pass revision.
	var stored []passsvc.Pass
	found, err := store.ReadJSON(h.paths.Snapshot("passes"), &stored)
	if err != nil || !found {
		t.Fatalf("pass snapshot missing: %v", err)
	}
	for index := range stored {
		if stored[index].ID == value.ID {
			stored[index].Window.Revision = 2
		}
	}
	if err := store.WriteJSON(h.paths.Snapshot("passes"), stored); err != nil {
		t.Fatal(err)
	}

	reloaded := reloadService(t, h.paths)
	verification, err := reloaded.Download(value.ID)
	if err != nil {
		t.Fatal(err)
	}
	if !verification.Intact || verification.Report.Revision != 1 {
		t.Fatalf("sealed report must keep its bound revision: %+v", verification)
	}
	if verification.RevisionCurrent || verification.CurrentRevision != 2 {
		t.Fatalf("expected revision drift to be flagged: %+v", verification)
	}
}

func TestTamperedReportFailsVerificationAndLeavesStateIntact(t *testing.T) {
	h := newHarness(t)
	value := h.createTrackingPass(t, 1)
	h.applyRFPlans(t, value.ID)
	h.converge(t, value.ID, 1)
	if _, err := h.service.Generate(value.ID); err != nil {
		t.Fatal(err)
	}

	path := h.paths.Delivery(value.ID)
	if err := os.Chmod(path, 0o644); err != nil {
		t.Fatal(err)
	}
	raw, err := os.ReadFile(path)
	if err != nil {
		t.Fatal(err)
	}
	raw[len(raw)-20] ^= 0xff
	if err := os.WriteFile(path, raw, 0o644); err != nil {
		t.Fatal(err)
	}

	if _, err := h.service.Download(value.ID); err == nil {
		t.Fatal("tampered report unexpectedly verified")
	}
	passAfter, _ := h.passes.Get(value.ID)
	if passAfter.Phase != passsvc.Completed {
		t.Fatalf("pass state changed after failed verification: %s", passAfter.Phase)
	}
}

func TestFailedPassProducesReportExplainingGaps(t *testing.T) {
	h := newHarness(t)
	value := h.createTrackingPass(t, 1) // no RF plans, no recording
	attempt, err := h.attempts.Begin(value.ID, "RF-01")
	if err != nil {
		t.Fatal(err)
	}
	if err := h.passes.BeginAcquisition(value.ID, attempt.ID); err != nil {
		t.Fatal(err)
	}
	if err := h.attempts.Deliver(receiver.AcquisitionResult{
		PassID: value.ID, AttemptID: attempt.ID, ChainID: "RF-01", ErrorCode: "NO-CARRIER",
	}); err != nil {
		t.Fatal(err)
	}

	verification, err := h.service.Generate(value.ID)
	if err != nil {
		t.Fatal(err)
	}
	report := verification.Report
	if report.Status != CompleteWithGaps {
		t.Fatalf("expected gapped report, got %s", report.Status)
	}
	codes := gapCodes(report.Gaps)
	for _, expected := range []string{"receiver.no_lock", "recording.no_segment", "decoder.no_epoch", "rf.plan_missing"} {
		if !codes[expected] {
			t.Fatalf("expected gap %s in %v", expected, codes)
		}
	}
	if !verification.Intact {
		t.Fatal("gapped report must still be sealed and intact")
	}
}

func TestReportFlagsDiscardedSymbolsAndCRCAndSequenceGaps(t *testing.T) {
	h := newHarness(t)
	value := h.createTrackingPass(t, 1)
	h.applyRFPlans(t, value.ID)
	// Sequence 1 then 3 leaves sequence 2 missing.
	h.converge(t, value.ID, 1, 3)
	h.decoders[value.ID] = decoderState{attempt: "att", epoch: 7, lost: 12}

	verification, err := h.service.Generate(value.ID)
	if err != nil {
		t.Fatal(err)
	}
	codes := gapCodes(verification.Report.Gaps)
	if !codes["decoder.symbols_discarded"] {
		t.Fatalf("expected discarded symbols gap: %v", codes)
	}
	if !codes["crc.sequence_gap"] || len(verification.Report.CRC.MissingSequences) != 1 {
		t.Fatalf("expected one sequence gap: %+v", verification.Report.CRC)
	}
}

func TestReportFlagsCorruptFrames(t *testing.T) {
	h := newHarness(t)
	value := h.createTrackingPass(t, 1)
	h.applyRFPlans(t, value.ID)
	h.converge(t, value.ID, 1)
	// Locate the sealed segment from the manager and flip a payload byte.
	segments := h.recorders.List()
	if len(segments) != 1 {
		t.Fatalf("expected one segment, got %d", len(segments))
	}
	path := h.paths.Recording(segments[0].ID)
	raw, err := os.ReadFile(path)
	if err != nil {
		t.Fatal(err)
	}
	raw[len(raw)-1] ^= 0xff // corrupt final payload byte, after the 28-byte header
	if err := os.WriteFile(path, raw, 0o644); err != nil {
		t.Fatal(err)
	}

	verification, err := h.service.Generate(value.ID)
	if err != nil {
		t.Fatal(err)
	}
	codes := gapCodes(verification.Report.Gaps)
	if !codes["crc.corrupt_frames"] || verification.Report.CRC.CorruptFrames != 1 {
		t.Fatalf("expected one corrupt frame gap: %+v %v", verification.Report.CRC, codes)
	}
}

func TestGenerateRejectsActivePass(t *testing.T) {
	h := newHarness(t)
	value := h.createTrackingPass(t, 1)
	if _, err := h.service.Generate(value.ID); err == nil {
		t.Fatal("active (planned) pass should not be deliverable")
	}
	if _, ok := h.service.Get(value.ID); ok {
		t.Fatal("no report should be cached for a rejected generation")
	}
}

func reloadService(t *testing.T, paths store.Paths) *Service {
	t.Helper()
	log := store.NewAppendLog(paths)
	trail := audit.NewTrail(log)
	rfController, err := rf.NewController(paths, trail, []string{"RF-01", "RF-02", "RF-03"})
	if err != nil {
		t.Fatal(err)
	}
	manager, err := recorder.NewManager(paths, trail)
	if err != nil {
		t.Fatal(err)
	}
	passes, err := passsvc.NewService(paths, manager, trail)
	if err != nil {
		t.Fatal(err)
	}
	dispatcher, err := receiver.NewAttemptDispatcher(paths, trail)
	if err != nil {
		t.Fatal(err)
	}
	service, err := NewService(paths, passes, dispatcher, manager, rfController, log, trail, fakeDecoders{})
	if err != nil {
		t.Fatal(err)
	}
	return service
}

func gapCodes(gaps []Gap) map[string]bool {
	codes := make(map[string]bool, len(gaps))
	for _, gap := range gaps {
		codes[gap.Code] = true
	}
	return codes
}

func fileSize(t *testing.T, path string) int64 {
	t.Helper()
	info, err := os.Stat(path)
	if err != nil {
		t.Fatal(err)
	}
	return info.Size()
}
