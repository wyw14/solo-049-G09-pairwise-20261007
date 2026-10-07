package api

import (
	"context"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"testing"

	passsvc "orbitlink/internal/pass"
	"orbitlink/internal/receiver"
	"orbitlink/internal/rf"
)

func newTestServer(t *testing.T, handler http.Handler) *httptest.Server {
	t.Helper()
	server := httptest.NewServer(handler)
	t.Cleanup(server.Close)
	return server
}

func TestDeliveryEndToEndLifecycle(t *testing.T) {
	runtime := newTestRuntime(t)
	value := runtime.Passes.List()[0]

	for _, chain := range []string{"RF-01", "RF-02"} {
		if _, err := runtime.RF.Apply(rf.Plan{PassID: value.ID, ChainID: chain, CenterHz: 2_245_000_000, DopplerHz: 12_000, Polarization: rf.RightCircular}); err != nil {
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
	results := []receiver.AcquisitionResult{
		{PassID: value.ID, AttemptID: attempt.ID, ChainID: "RF-01", Locked: true, Synced: true, Epoch: 4},
		{PassID: value.ID, AttemptID: attempt.ID, ChainID: "RF-02", Locked: true, Synced: true, Epoch: 4},
	}
	decision, err := runtime.Passes.AcceptDiversity(value.ID, results)
	if err != nil || !decision.Ready {
		t.Fatalf("diversity did not converge: %#v %v", decision, err)
	}
	segment, found := runtime.Recorder.ActiveForPass(value.ID)
	if !found {
		t.Fatal("recording did not start")
	}
	session, err := runtime.NewDecoderSession(value.ID, segment.ID)
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

	router, err := NewRouter(runtime)
	if err != nil {
		t.Fatal(err)
	}
	server := newTestServer(t, router)
	base := server.URL + "/api/passes/" + value.ID + "/delivery"

	resp := requestJSON(t, server.Client(), http.MethodPost, base, "{}")
	if resp.StatusCode != http.StatusCreated {
		t.Fatalf("first delivery POST status = %d, want 201", resp.StatusCode)
	}
	var first struct {
		Report struct {
			ID       string `json:"id"`
			Revision int64  `json:"revision"`
			Status   string `json:"status"`
			SHA256   string `json:"sha256"`
		} `json:"report"`
		Intact bool `json:"intact"`
		Reused bool `json:"reused"`
	}
	decodeBody(t, resp, &first)
	if !first.Intact || first.Reused || first.Report.SHA256 == "" {
		t.Fatalf("unexpected first delivery: %+v", first)
	}
	if first.Report.Revision != value.Window.Revision || first.Report.Status != "complete" {
		t.Fatalf("unexpected report binding/status: %+v", first.Report)
	}

	// Repeat POST must verify rather than rebuild: 200 + reused + same digest.
	resp = requestJSON(t, server.Client(), http.MethodPost, base, "{}")
	if resp.StatusCode != http.StatusOK {
		t.Fatalf("repeat delivery POST status = %d, want 200", resp.StatusCode)
	}
	var again struct {
		Report struct {
			SHA256 string `json:"sha256"`
		} `json:"report"`
		Intact bool `json:"intact"`
		Reused bool `json:"reused"`
	}
	decodeBody(t, resp, &again)
	if !again.Intact || !again.Reused || again.Report.SHA256 != first.Report.SHA256 {
		t.Fatalf("repeat delivery did not verify the sealed report: %+v", again)
	}

	resp = requestJSON(t, server.Client(), http.MethodGet, base, "")
	if resp.StatusCode != http.StatusOK {
		t.Fatalf("GET delivery status = %d", resp.StatusCode)
	}
	decodeBody(t, resp, &again)
	if !again.Intact || !again.Reused {
		t.Fatalf("GET delivery did not verify: %+v", again)
	}

	listResp, err := server.Client().Get(server.URL + "/api/deliveries")
	if err != nil {
		t.Fatal(err)
	}
	defer listResp.Body.Close()
	if listResp.StatusCode != http.StatusOK {
		t.Fatalf("list deliveries status = %d", listResp.StatusCode)
	}
	var list struct {
		Items []struct {
			PassID string `json:"pass_id"`
		} `json:"items"`
	}
	if err := json.NewDecoder(listResp.Body).Decode(&list); err != nil {
		t.Fatal(err)
	}
	if len(list.Items) != 1 || list.Items[0].PassID != value.ID {
		t.Fatalf("delivery list mismatch: %+v", list.Items)
	}

	// The pass must remain completed: delivery never mutates task state.
	after, found := runtime.Passes.Get(value.ID)
	if !found || after.Phase != passsvc.Completed {
		t.Fatalf("pass state changed through delivery: %+v found=%v", after, found)
	}
}

func TestDeliveryRejectsUnknownPass(t *testing.T) {
	runtime := newTestRuntime(t)
	router, err := NewRouter(runtime)
	if err != nil {
		t.Fatal(err)
	}
	server := newTestServer(t, router)
	resp := requestJSON(t, server.Client(), http.MethodPost, server.URL+"/api/passes/does-not-exist/delivery", "{}")
	if resp.StatusCode == http.StatusCreated || resp.StatusCode == http.StatusOK {
		t.Fatalf("unknown pass delivery unexpectedly succeeded: %d", resp.StatusCode)
	}
	resp.Body.Close()
}
