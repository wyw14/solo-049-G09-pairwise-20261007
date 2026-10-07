package api

import (
	"context"
	"encoding/json"
	"fmt"
	"net/http"
	"net/http/httptest"
	"os"
	"testing"
	"time"

	"orbitlink/internal/audit"
	passsvc "orbitlink/internal/pass"
	"orbitlink/internal/receiver"
	"orbitlink/internal/recorder"
	"orbitlink/internal/rf"
)

func trackAndFinalize(t *testing.T, runtime *Runtime) passsvc.Pass {
	t.Helper()
	value := runtime.Passes.List()[0]
	for _, chainID := range value.RFChains {
		if _, err := runtime.RF.Apply(rf.Plan{PassID: value.ID, ChainID: chainID, CenterHz: 2_245_000_000, DopplerHz: 12_000, Polarization: rf.RightCircular}); err != nil {
			t.Fatal(err)
		}
	}
	attempt, err := runtime.Attempts.Begin(value.ID, "RF-01")
	if err != nil {
		t.Fatal(err)
	}
	if err := runtime.Passes.BeginAcquisition(value.ID, attempt.ID); err != nil {
		t.Fatal(err)
	}
	decision, err := runtime.Passes.AcceptDiversity(value.ID, []receiver.AcquisitionResult{
		{PassID: value.ID, AttemptID: attempt.ID, ChainID: "RF-01", Locked: true, Synced: true, Epoch: 1},
		{PassID: value.ID, AttemptID: "manual-rf02", ChainID: "RF-02", Locked: true, Synced: true, Epoch: 1},
	})
	if err != nil || !decision.Ready {
		t.Fatalf("diversity did not converge: %#v %v", decision, err)
	}
	session, err := runtime.receiverSession(value.ID)
	if err != nil {
		t.Fatal(err)
	}
	if _, err := session.OnLock(attempt.ID); err != nil {
		t.Fatal(err)
	}
	if _, err := session.Feed(attempt.ID, make([]byte, 128)); err != nil {
		t.Fatal(err)
	}
	if _, err := runtime.Finalizer.Finalize(context.Background(), value.ID, "RF-01"); err != nil {
		t.Fatal(err)
	}
	value, _ = runtime.Passes.Get(value.ID)
	return value
}

func TestDeliveryReportAggregatesPassData(t *testing.T) {
	runtime := newTestRuntime(t)
	value := trackAndFinalize(t, runtime)

	report, created, err := runtime.Deliveries.Generate(value.ID)
	if err != nil || !created {
		t.Fatalf("generate failed: created=%v err=%v", created, err)
	}
	if report.PassID != value.ID || report.Revision != value.Window.Revision {
		t.Fatalf("report is not bound to pass revision: %#v", report)
	}
	if !report.Complete || len(report.Gaps) != 0 {
		t.Fatalf("expected a gap-free report, got %#v", report.Gaps)
	}
	if len(report.Receiver.Attempts) != 1 || report.Receiver.Attempts[0].ChainID != "RF-01" {
		t.Fatalf("receiver attempts missing: %#v", report.Receiver)
	}
	if report.Decoder.CurrentEpoch != 1 || len(report.Decoder.Epochs) != 1 {
		t.Fatalf("decoder epochs missing: %#v", report.Decoder)
	}
	if report.Recording == nil || report.Recording.Status != recorder.Sealed || report.Recording.FramesWritten != 2 {
		t.Fatalf("recording summary incomplete: %#v", report.Recording)
	}
	if report.Recording.PayloadSHA256 == "" || report.Recording.FileBytes != 2*(28+64) {
		t.Fatalf("recording payload digest missing: %#v", report.Recording)
	}
	if len(report.CRCIndex) != 2 || report.CRCIndex[0].Sequence != 1 || report.CRCIndex[1].Sequence != 2 {
		t.Fatalf("crc index incomplete: %#v", report.CRCIndex)
	}
	if len(report.RFPlans) != 2 {
		t.Fatalf("rf plans missing: %#v", report.RFPlans)
	}
	if len(report.AuditEvents) == 0 {
		t.Fatal("audit events missing from report")
	}
	if report.Checksum == "" || report.Checksum != report.ComputeChecksum() {
		t.Fatal("report checksum does not verify")
	}
}

func TestDeliveryReportIsImmutablePerRevision(t *testing.T) {
	runtime := newTestRuntime(t)
	value := trackAndFinalize(t, runtime)

	report, created, err := runtime.Deliveries.Generate(value.ID)
	if err != nil || !created {
		t.Fatalf("generate failed: created=%v err=%v", created, err)
	}
	again, createdAgain, err := runtime.Deliveries.Generate(value.ID)
	if err != nil {
		t.Fatal(err)
	}
	if createdAgain {
		t.Fatal("regenerating an existing revision must not create a new report")
	}
	if again.ID != report.ID || again.Checksum != report.Checksum || !again.GeneratedAt.Equal(report.GeneratedAt) {
		t.Fatal("regeneration changed the immutable report")
	}
}

func TestDeliveryDownloadOnlyVerifies(t *testing.T) {
	runtime := newTestRuntime(t)
	value := trackAndFinalize(t, runtime)
	report, _, err := runtime.Deliveries.Generate(value.ID)
	if err != nil {
		t.Fatal(err)
	}

	before, _ := runtime.Passes.Get(value.ID)
	auditBefore := len(runtime.Audit.List(audit.Query{}))
	for i := 0; i < 2; i++ {
		downloaded, verified, err := runtime.Deliveries.Download(value.ID, 0)
		if err != nil || !verified {
			t.Fatalf("download %d failed: verified=%v err=%v", i, verified, err)
		}
		if downloaded.ID != report.ID || downloaded.Checksum != report.Checksum {
			t.Fatal("download returned a different report")
		}
	}
	after, _ := runtime.Passes.Get(value.ID)
	if !after.UpdatedAt.Equal(before.UpdatedAt) || after.Phase != before.Phase {
		t.Fatal("download modified pass state")
	}
	if len(runtime.Audit.List(audit.Query{})) != auditBefore {
		t.Fatal("download wrote audit events")
	}
	if _, _, err := runtime.Deliveries.Download(value.ID, 99); err == nil {
		t.Fatal("download of an ungenerated revision should fail")
	}
}

func TestDeliveryDownloadDetectsTampering(t *testing.T) {
	runtime := newTestRuntime(t)
	value := trackAndFinalize(t, runtime)
	if _, _, err := runtime.Deliveries.Generate(value.ID); err != nil {
		t.Fatal(err)
	}
	path := runtime.Paths.Delivery(fmt.Sprintf("%s-r%d", value.ID, value.Window.Revision))
	data, err := os.ReadFile(path)
	if err != nil {
		t.Fatal(err)
	}
	var document map[string]any
	if err := json.Unmarshal(data, &document); err != nil {
		t.Fatal(err)
	}
	document["complete"] = false
	raw, err := json.Marshal(document)
	if err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(path, raw, 0o644); err != nil {
		t.Fatal(err)
	}
	if _, _, err := runtime.Deliveries.Download(value.ID, 0); err == nil {
		t.Fatal("tampered report passed integrity verification")
	}
}

func TestDeliveryReportAnnotatesGaps(t *testing.T) {
	runtime := newTestRuntime(t)
	now := runtime.Clock.Now()
	value, err := runtime.Passes.Create(passsvc.CreateRequest{SatelliteID: "SAT-A12", AntennaID: "ANT-01", RFChains: []string{"RF-01", "RF-02"}, RequiredReceiverChains: []string{"RF-01", "RF-02"}, AOS: now.Add(time.Minute), LOS: now.Add(9 * time.Minute), Revision: 1, OwnerStation: "north"})
	if err != nil {
		t.Fatal(err)
	}
	attemptA, err := runtime.Attempts.Begin(value.ID, "RF-01")
	if err != nil {
		t.Fatal(err)
	}
	attemptB, err := runtime.Attempts.Begin(value.ID, "RF-02")
	if err != nil {
		t.Fatal(err)
	}
	if err := runtime.Passes.BeginAcquisition(value.ID, attemptA.ID); err != nil {
		t.Fatal(err)
	}
	// Only RF-01 gets a plan; RF-02 stays unplanned.
	if _, err := runtime.RF.Apply(rf.Plan{PassID: value.ID, ChainID: "RF-01", CenterHz: 2_245_000_000, DopplerHz: 12_000, Polarization: rf.RightCircular}); err != nil {
		t.Fatal(err)
	}
	if _, err := runtime.Passes.AcceptDiversity(value.ID, []receiver.AcquisitionResult{
		{PassID: value.ID, AttemptID: attemptA.ID, ChainID: "RF-01", Locked: true, Synced: true, Epoch: 1},
		{PassID: value.ID, AttemptID: attemptB.ID, ChainID: "RF-02", Locked: true, Synced: true, Epoch: 1},
	}); err != nil {
		t.Fatal(err)
	}
	// A failed acquisition result is kept in the attempt record.
	if err := runtime.Attempts.Deliver(receiver.AcquisitionResult{PassID: value.ID, AttemptID: attemptB.ID, ChainID: "RF-02", Locked: false, ErrorCode: "SNR-LOW"}); err != nil {
		t.Fatal(err)
	}
	// Lock attempt A, feed a partial frame, then relock on B: symbols are discarded.
	session, err := runtime.receiverSession(value.ID)
	if err != nil {
		t.Fatal(err)
	}
	if _, err := session.OnLock(attemptA.ID); err != nil {
		t.Fatal(err)
	}
	if _, err := session.Feed(attemptA.ID, make([]byte, 10)); err != nil {
		t.Fatal(err)
	}
	if _, err := session.OnLock(attemptB.ID); err != nil {
		t.Fatal(err)
	}
	// One full frame stays buffered and is never drained.
	if _, err := session.Feed(attemptB.ID, make([]byte, 64)); err != nil {
		t.Fatal(err)
	}

	report, created, err := runtime.Deliveries.Generate(value.ID)
	if err != nil || !created {
		t.Fatalf("generate failed: created=%v err=%v", created, err)
	}
	if report.Complete {
		t.Fatal("report with known gaps must not be complete")
	}
	codes := make(map[string]bool)
	for _, gap := range report.Gaps {
		codes[gap.Code] = true
	}
	for _, expected := range []string{"pass.not-completed", "acquisition.failed", "decoder.symbols-lost", "recording.frames-buffered", "rf.plan-missing"} {
		if !codes[expected] {
			t.Fatalf("gap %s missing from report: %#v", expected, report.Gaps)
		}
	}
	if report.Decoder.LostSymbols != 10 {
		t.Fatalf("expected 10 lost symbols, got %d", report.Decoder.LostSymbols)
	}
	if report.Recording == nil || report.Recording.FramesBuffered != 1 {
		t.Fatalf("buffered frame not reported: %#v", report.Recording)
	}
}

func TestDeliveryEndpoints(t *testing.T) {
	runtime := newTestRuntime(t)
	router, err := NewRouter(runtime)
	if err != nil {
		t.Fatal(err)
	}
	server := httptest.NewServer(router)
	defer server.Close()
	passID := runtime.Passes.List()[0].ID
	base := server.URL + "/api/passes/" + passID

	response, err := server.Client().Get(base + "/delivery")
	if err != nil {
		t.Fatal(err)
	}
	if response.StatusCode != http.StatusUnprocessableEntity {
		t.Fatalf("download before generate returned %d", response.StatusCode)
	}
	_ = response.Body.Close()

	response, err = server.Client().Post(base+"/delivery", "application/json", nil)
	if err != nil {
		t.Fatal(err)
	}
	if response.StatusCode != http.StatusCreated {
		t.Fatalf("generate returned %d", response.StatusCode)
	}
	var generated struct {
		Created bool `json:"created"`
		Report  struct {
			ID       string `json:"id"`
			Revision int64  `json:"revision"`
			Checksum string `json:"checksum"`
		} `json:"report"`
	}
	decodeBody(t, response, &generated)
	if !generated.Created || generated.Report.ID == "" || generated.Report.Revision != 1 {
		t.Fatalf("unexpected generate response: %#v", generated)
	}

	response, err = server.Client().Post(base+"/delivery", "application/json", nil)
	if err != nil {
		t.Fatal(err)
	}
	if response.StatusCode != http.StatusOK {
		t.Fatalf("regenerate returned %d", response.StatusCode)
	}
	var regenerated struct {
		Created bool `json:"created"`
		Report  struct {
			ID string `json:"id"`
		} `json:"report"`
	}
	decodeBody(t, response, &regenerated)
	if regenerated.Created || regenerated.Report.ID != generated.Report.ID {
		t.Fatal("regenerate did not return the existing immutable report")
	}

	response, err = server.Client().Get(base + "/delivery")
	if err != nil {
		t.Fatal(err)
	}
	if response.StatusCode != http.StatusOK {
		t.Fatalf("download returned %d", response.StatusCode)
	}
	var downloaded struct {
		Verified bool   `json:"verified"`
		Checksum string `json:"checksum"`
	}
	decodeBody(t, response, &downloaded)
	if !downloaded.Verified || downloaded.Checksum != generated.Report.Checksum {
		t.Fatalf("download failed verification: %#v", downloaded)
	}

	response, err = server.Client().Get(base + "/delivery?revision=abc")
	if err != nil {
		t.Fatal(err)
	}
	if response.StatusCode != http.StatusUnprocessableEntity {
		t.Fatalf("invalid revision returned %d", response.StatusCode)
	}
	_ = response.Body.Close()

	response, err = server.Client().Get(base + "/deliveries")
	if err != nil {
		t.Fatal(err)
	}
	if response.StatusCode != http.StatusOK {
		t.Fatalf("list returned %d", response.StatusCode)
	}
	var listed struct {
		Items []struct {
			ID       string `json:"id"`
			Revision int64  `json:"revision"`
		} `json:"items"`
	}
	decodeBody(t, response, &listed)
	if len(listed.Items) != 1 || listed.Items[0].ID != generated.Report.ID {
		t.Fatalf("unexpected delivery list: %#v", listed.Items)
	}

	response, err = server.Client().Get(server.URL + "/api/passes/unknown-pass/delivery")
	if err != nil {
		t.Fatal(err)
	}
	if response.StatusCode != http.StatusUnprocessableEntity {
		t.Fatalf("unknown pass returned %d", response.StatusCode)
	}
	_ = response.Body.Close()
}

func TestDeliveryReportSurvivesRestart(t *testing.T) {
	runtime := newTestRuntime(t)
	value := trackAndFinalize(t, runtime)
	report, created, err := runtime.Deliveries.Generate(value.ID)
	if err != nil || !created {
		t.Fatalf("generate failed: created=%v err=%v", created, err)
	}

	restarted, err := NewRuntime(runtime.StateRoot)
	if err != nil {
		t.Fatal(err)
	}
	again, created, err := restarted.Deliveries.Generate(value.ID)
	if err != nil {
		t.Fatal(err)
	}
	if created || again.ID != report.ID || again.Checksum != report.Checksum {
		t.Fatal("restart produced a different report for the same revision")
	}
	downloaded, verified, err := restarted.Deliveries.Download(value.ID, report.Revision)
	if err != nil || !verified || downloaded.ID != report.ID {
		t.Fatalf("download after restart failed: verified=%v err=%v", verified, err)
	}
	summaries, err := restarted.Deliveries.List(value.ID)
	if err != nil || len(summaries) != 1 || summaries[0].Checksum != report.Checksum {
		t.Fatalf("list after restart failed: %#v err=%v", summaries, err)
	}
	if summaries[0].ID != report.ID {
		t.Fatal("summary id mismatch")
	}
}
