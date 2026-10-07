package delivery

import (
	"time"

	"orbitlink/internal/audit"
	passsvc "orbitlink/internal/pass"
	"orbitlink/internal/recorder"
	"orbitlink/internal/rf"
)

// Status is the headline disposition of an immutable delivery report.
type Status string

const (
	// Complete means every expected data source was present and consistent.
	Complete Status = "complete"
	// CompleteWithGaps means the pass data was delivered, but one or more
	// domains are missing or inconsistent and are explained in Gaps.
	CompleteWithGaps Status = "complete_with_gaps"
)

// Gap explains one missing or inconsistent part of a delivered pass.
type Gap struct {
	Domain   string         `json:"domain"`
	Code     string         `json:"code"`
	Message  string         `json:"message"`
	Severity audit.Severity `json:"severity"`
}

// ReceiverSummary aggregates acquisition results received for the pass.
type ReceiverSummary struct {
	Attempts        int      `json:"attempts"`
	LockedAttempts  int      `json:"locked_attempts"`
	FailedAttempts  int      `json:"failed_attempts"`
	PendingAttempts int      `json:"pending_attempts"`
	CurrentAttempt  string   `json:"current_attempt_id,omitempty"`
	RequiredChains  []string `json:"required_chains"`
	ChainsLocked    []string `json:"chains_locked"`
}

// DecoderSummary captures the decoder epoch boundary and symbol losses.
type DecoderSummary struct {
	Epoch           int64  `json:"epoch"`
	ActiveAttemptID string `json:"active_attempt_id,omitempty"`
	EpochStarts     int    `json:"epoch_starts"`
	LostSymbols     int    `json:"lost_symbols"`
}

// RecordingSummary describes the segment recorded for the pass.
type RecordingSummary struct {
	SegmentID       string                 `json:"segment_id,omitempty"`
	Status          recorder.SegmentStatus `json:"status,omitempty"`
	OwnerStation    string                 `json:"owner_station,omitempty"`
	OwnerGeneration int64                  `json:"owner_generation,omitempty"`
	FramesWritten   int                    `json:"frames_written"`
	FramesBuffered  int                    `json:"frames_buffered"`
	FilePresent     bool                   `json:"file_present"`
	FileSize        int64                  `json:"file_size"`
}

// CRCSummary is the frame CRC index result for the recording file.
type CRCSummary struct {
	FramesIndexed    int      `json:"frames_indexed"`
	ValidFrames      int      `json:"valid_frames"`
	CorruptFrames    int      `json:"corrupt_frames"`
	Truncated        bool     `json:"truncated"`
	MissingSequences []uint64 `json:"missing_sequences,omitempty"`
}

// RFChainPlan is the RF plan observed on one chain at delivery time.
type RFChainPlan struct {
	ChainID         string          `json:"chain_id"`
	Bound           bool            `json:"bound"`
	CenterHz        int64           `json:"center_hz"`
	DopplerHz       int64           `json:"doppler_hz"`
	Polarization    rf.Polarization `json:"polarization,omitempty"`
	TransmitEnabled bool            `json:"transmit_enabled"`
}

// RFSummary lists the RF plans covering the pass chains.
type RFSummary struct {
	PlannedChains []string      `json:"planned_chains"`
	Chains        []RFChainPlan `json:"chains"`
}

// AuditSummary counts the audit trail attributable to the pass.
type AuditSummary struct {
	Events      int        `json:"events"`
	Warnings    int        `json:"warnings"`
	Criticals   int        `json:"criticals"`
	LastEventAt *time.Time `json:"last_event_at,omitempty"`
}

// Artifact points at one durable file covered by the report.
type Artifact struct {
	Name      string `json:"name"`
	Path      string `json:"path"`
	SegmentID string `json:"segment_id"`
	Size      int64  `json:"size"`
	Frames    int    `json:"frames"`
}

// Report is the immutable, revision-bound delivery manifest for one pass.
type Report struct {
	ID          string           `json:"id"`
	PassID      string           `json:"pass_id"`
	Revision    int64            `json:"revision"`
	SatelliteID string           `json:"satellite_id"`
	AntennaID   string           `json:"antenna_id"`
	AOS         time.Time        `json:"aos"`
	LOS         time.Time        `json:"los"`
	Phase       passsvc.Phase    `json:"phase"`
	GeneratedAt time.Time        `json:"generated_at"`
	Status      Status           `json:"status"`
	Gaps        []Gap            `json:"gaps"`
	Receiver    ReceiverSummary  `json:"receiver"`
	Decoder     DecoderSummary   `json:"decoder"`
	Recording   RecordingSummary `json:"recording"`
	CRC         CRCSummary       `json:"crc"`
	RF          RFSummary        `json:"rf"`
	Audit       AuditSummary     `json:"audit"`
	Artifacts   []Artifact       `json:"artifacts"`
	// SHA256 covers the canonical JSON of every field above except this one.
	SHA256 string `json:"sha256"`
}

// Verification is returned for both first generation and repeat downloads.
type Verification struct {
	Report          Report `json:"report"`
	Intact          bool   `json:"intact"`
	Reused          bool   `json:"reused"`
	RevisionCurrent bool   `json:"revision_current"`
	CurrentRevision int64  `json:"current_revision"`
}
