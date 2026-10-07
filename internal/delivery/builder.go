package delivery

import (
	"fmt"
	"sort"
	"time"

	"orbitlink/internal/audit"
	passsvc "orbitlink/internal/pass"
	"orbitlink/internal/receiver"
	"orbitlink/internal/recorder"
	"orbitlink/internal/rf"
)

// Input gathers the read-only state aggregated into one delivery report.
type Input struct {
	Pass           passsvc.Pass
	Attempts       []receiver.Attempt
	DecoderAttempt string
	DecoderEpoch   int64
	LostSymbols    int
	Segment        recorder.Segment
	SegmentFound   bool
	Index          recorder.FrameIndex
	IndexPresent   bool
	RFStates       []rf.State
	AuditEvents    []audit.Event
	RecordingPath  string
}

type builder struct {
	pass passsvc.Pass
	gaps []Gap
}

func buildReport(input Input) Report {
	b := &builder{pass: input.Pass}
	report := Report{
		PassID:      input.Pass.ID,
		Revision:    input.Pass.Window.Revision,
		SatelliteID: input.Pass.SatelliteID,
		AntennaID:   input.Pass.AntennaID,
		AOS:         input.Pass.Window.AOS,
		LOS:         input.Pass.Window.LOS,
		Phase:       input.Pass.Phase,
		GeneratedAt: time.Now().UTC(),
		Gaps:        []Gap{},
		Artifacts:   []Artifact{},
	}

	switch input.Pass.Phase {
	case passsvc.Completed, passsvc.Sealed, passsvc.Failed, passsvc.Canceled:
	default:
		b.add("pass", "pass.active", "report generated before the pass reached a terminal phase", audit.Warning)
	}

	report.Receiver = b.receiver(input)
	report.Decoder = b.decoder(input)
	report.Recording, report.CRC = b.recording(input)
	report.RF = b.rf(input)
	report.Audit = b.auditEvents(input)

	if input.IndexPresent {
		report.Artifacts = append(report.Artifacts, Artifact{
			Name:      input.Segment.ID + ".frames",
			Path:      input.RecordingPath,
			SegmentID: input.Segment.ID,
			Size:      input.Index.FileSize,
			Frames:    len(input.Index.Frames),
		})
	}

	if len(b.gaps) == 0 {
		report.Status = Complete
	} else {
		report.Status = CompleteWithGaps
	}
	report.Gaps = b.gaps
	return report
}

func (b *builder) add(domain, code, message string, severity audit.Severity) {
	b.gaps = append(b.gaps, Gap{Domain: domain, Code: code, Message: message, Severity: severity})
}

func (b *builder) receiver(input Input) ReceiverSummary {
	summary := ReceiverSummary{RequiredChains: append([]string(nil), b.pass.RequiredReceiverChains...), ChainsLocked: []string{}}
	lockedChains := map[string]bool{}
	for _, attempt := range input.Attempts {
		if attempt.PassID != b.pass.ID {
			continue
		}
		summary.Attempts++
		switch attempt.Status {
		case receiver.AttemptLocked:
			summary.LockedAttempts++
			lockedChains[attempt.ChainID] = true
		case receiver.AttemptFailed:
			summary.FailedAttempts++
		default:
			summary.PendingAttempts++
		}
		if attempt.ID == b.pass.CurrentAttemptID {
			summary.CurrentAttempt = attempt.ID
		}
	}

	// A started segment only exists once the diversity policy confirmed every
	// required chain locked and synced on a common epoch, so it is persisted
	// proof of convergence even when attempt statuses stay "pending".
	converged := input.SegmentFound
	if converged {
		for _, chain := range summary.RequiredChains {
			lockedChains[chain] = true
		}
	}
	for chain := range lockedChains {
		summary.ChainsLocked = append(summary.ChainsLocked, chain)
	}
	sort.Strings(summary.ChainsLocked)

	if converged {
		return summary
	}
	if summary.Attempts == 0 {
		b.add("receiver", "receiver.no_attempts", "no acquisition attempts were recorded for the pass", audit.Warning)
	}
	if summary.LockedAttempts == 0 {
		b.add("receiver", "receiver.no_lock", "no receiver attempt achieved carrier lock and sync", audit.Critical)
	}
	if summary.PendingAttempts > 0 {
		b.add("receiver", "receiver.attempts_pending", fmt.Sprintf("%d acquisition attempt(s) never reported a result", summary.PendingAttempts), audit.Warning)
	}
	if summary.FailedAttempts > 0 {
		b.add("receiver", "receiver.attempts_failed", fmt.Sprintf("%d acquisition attempt(s) failed", summary.FailedAttempts), audit.Warning)
	}
	for _, chain := range summary.RequiredChains {
		if !lockedChains[chain] {
			b.add("receiver", "receiver.chain_not_locked", fmt.Sprintf("required receiver chain %s never locked", chain), audit.Warning)
		}
	}
	return summary
}

func (b *builder) decoder(input Input) DecoderSummary {
	summary := DecoderSummary{Epoch: input.DecoderEpoch, ActiveAttemptID: input.DecoderAttempt, EpochStarts: int(input.DecoderEpoch)}
	if input.DecoderEpoch == 0 {
		b.add("decoder", "decoder.no_epoch", "decoder never started an epoch for the pass", audit.Warning)
	}
	if input.LostSymbols > 0 {
		b.add("decoder", "decoder.symbols_discarded", fmt.Sprintf("%d buffered symbol(s) were discarded across epoch restarts", input.LostSymbols), audit.Warning)
	}
	return summary
}

func (b *builder) recording(input Input) (RecordingSummary, CRCSummary) {
	summary := RecordingSummary{}
	crc := CRCSummary{}
	if !input.SegmentFound || input.Segment.ID == "" {
		b.add("recording", "recording.no_segment", "pass has no recording segment", audit.Critical)
		return summary, crc
	}
	segment := input.Segment
	summary = RecordingSummary{
		SegmentID: segment.ID, Status: segment.Status, OwnerStation: segment.OwnerStation,
		OwnerGeneration: segment.OwnerGeneration, FramesWritten: segment.FramesWritten,
		FramesBuffered: segment.FramesBuffered,
	}
	if input.IndexPresent {
		summary.FilePresent = true
		summary.FileSize = input.Index.FileSize
		crc = CRCSummary{
			FramesIndexed:    len(input.Index.Frames),
			ValidFrames:      input.Index.ValidFrames,
			CorruptFrames:    input.Index.CorruptFrames,
			Truncated:        input.Index.Truncated,
			MissingSequences: append([]uint64(nil), input.Index.MissingSequence...),
		}
	}

	switch segment.Status {
	case recorder.Aborted:
		b.add("recording", "recording.aborted", "recording segment was aborted: "+segment.SealReason, audit.Warning)
	case recorder.Sealed:
	default:
		b.add("recording", "recording.not_sealed", "recording segment is "+string(segment.Status)+" rather than sealed", audit.Warning)
	}
	if segment.FramesBuffered > 0 {
		b.add("recording", "recording.frames_buffered", fmt.Sprintf("%d frame(s) stayed buffered and never reached disk", segment.FramesBuffered), audit.Warning)
	}
	if segment.FramesWritten == 0 {
		b.add("recording", "recording.no_frames", "no frames were written for the pass", audit.Warning)
	}
	if !input.IndexPresent {
		b.add("recording", "recording.file_missing", "durable recording file is absent", audit.Critical)
		return summary, crc
	}
	if input.Index.Truncated {
		b.add("crc", "crc.truncated_file", fmt.Sprintf("recording file ends with %d trailing byte(s) of a partial frame", input.Index.TrailingBytes), audit.Critical)
	}
	if input.Index.CorruptFrames > 0 {
		b.add("crc", "crc.corrupt_frames", fmt.Sprintf("%d frame(s) failed CRC32 verification", input.Index.CorruptFrames), audit.Critical)
	}
	if len(input.Index.MissingSequence) > 0 {
		b.add("crc", "crc.sequence_gap", fmt.Sprintf("%d frame sequence number(s) are missing from the index", len(input.Index.MissingSequence)), audit.Warning)
	}
	return summary, crc
}

func (b *builder) rf(input Input) RFSummary {
	summary := RFSummary{PlannedChains: append([]string(nil), b.pass.RFChains...), Chains: []RFChainPlan{}}
	stateByChain := make(map[string]rf.State, len(input.RFStates))
	for _, state := range input.RFStates {
		stateByChain[state.ChainID] = state
	}
	for _, chainID := range b.pass.RFChains {
		state, found := stateByChain[chainID]
		plan := RFChainPlan{ChainID: chainID}
		bound := found && state.PassID == b.pass.ID && state.CenterHz > 0
		if bound {
			plan = RFChainPlan{
				ChainID: chainID, Bound: true, CenterHz: state.CenterHz, DopplerHz: state.DopplerHz,
				Polarization: state.Polarization, TransmitEnabled: state.TransmitEnabled,
			}
		}
		summary.Chains = append(summary.Chains, plan)
		if !bound {
			b.add("rf", "rf.plan_missing", fmt.Sprintf("RF chain %s has no plan bound to the pass", chainID), audit.Warning)
		}
	}
	return summary
}

func (b *builder) auditEvents(input Input) AuditSummary {
	summary := AuditSummary{}
	var last time.Time
	for _, event := range input.AuditEvents {
		summary.Events++
		switch event.Severity {
		case audit.Warning:
			summary.Warnings++
		case audit.Critical:
			summary.Criticals++
		}
		if event.At.After(last) {
			last = event.At
		}
	}
	if !last.IsZero() {
		summary.LastEventAt = &last
	}
	if summary.Criticals > 0 {
		b.add("audit", "audit.critical_events", fmt.Sprintf("audit trail for the pass contains %d critical event(s)", summary.Criticals), audit.Critical)
	}
	return summary
}

// attributableToPass keeps audit events tied to the pass or its segment.
func attributableToPass(event audit.Event, passID, segmentID string) bool {
	if event.Subject == passID || (segmentID != "" && event.Subject == segmentID) {
		return true
	}
	if value, ok := event.Fields["pass_id"].(string); ok && value == passID {
		return true
	}
	return false
}
