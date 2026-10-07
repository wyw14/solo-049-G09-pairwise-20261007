package delivery

import (
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"time"

	"orbitlink/internal/audit"
	"orbitlink/internal/pass"
	"orbitlink/internal/receiver"
	"orbitlink/internal/recorder"
)

// Gap annotates one known hole in the delivered pass data.
type Gap struct {
	Code   string `json:"code"`
	Detail string `json:"detail"`
}

type PassSummary struct {
	ID            string     `json:"id"`
	SatelliteID   string     `json:"satellite_id"`
	AntennaID     string     `json:"antenna_id"`
	Phase         pass.Phase `json:"phase"`
	AOS           time.Time  `json:"aos"`
	LOS           time.Time  `json:"los"`
	FailureReason string     `json:"failure_reason,omitempty"`
}

type AttemptSummary struct {
	ID         string                 `json:"id"`
	ChainID    string                 `json:"chain_id"`
	Number     int64                  `json:"number"`
	Status     receiver.AttemptStatus `json:"status"`
	Epoch      int64                  `json:"epoch,omitempty"`
	ErrorCode  string                 `json:"error_code,omitempty"`
	StartedAt  time.Time              `json:"started_at"`
	FinishedAt time.Time              `json:"finished_at,omitempty"`
}

type ReceiverSummary struct {
	Attempts         []AttemptSummary `json:"attempts"`
	CurrentAttemptID string           `json:"current_attempt_id,omitempty"`
	Locked           int              `json:"locked"`
	Failed           int              `json:"failed"`
}

type EpochSummary struct {
	Epoch            int64  `json:"epoch"`
	AttemptID        string `json:"attempt_id"`
	DiscardedSymbols int    `json:"discarded_symbols"`
}

type DecoderSummary struct {
	CurrentEpoch int64          `json:"current_epoch"`
	Epochs       []EpochSummary `json:"epochs"`
	LostSymbols  int            `json:"lost_symbols"`
}

type RecordingSummary struct {
	SegmentID       string                 `json:"segment_id"`
	Status          recorder.SegmentStatus `json:"status"`
	OwnerStation    string                 `json:"owner_station"`
	OwnerGeneration int64                  `json:"owner_generation"`
	FramesWritten   int                    `json:"frames_written"`
	FramesBuffered  int                    `json:"frames_buffered"`
	StartedAt       time.Time              `json:"started_at"`
	SealedAt        time.Time              `json:"sealed_at,omitempty"`
	SealReason      string                 `json:"seal_reason,omitempty"`
	FileBytes       int64                  `json:"file_bytes"`
	PayloadSHA256   string                 `json:"payload_sha256,omitempty"`
}

type CRCEntry struct {
	Sequence uint64 `json:"sequence"`
	Epoch    int64  `json:"epoch"`
	CRC32    uint32 `json:"crc32"`
}

type RFPlanSummary struct {
	ChainID   string    `json:"chain_id"`
	CenterHz  int64     `json:"center_hz"`
	DopplerHz int64     `json:"doppler_hz"`
	AppliedAt time.Time `json:"applied_at"`
}

// Report is the immutable delivery document for one pass revision.
type Report struct {
	ID          string            `json:"id"`
	PassID      string            `json:"pass_id"`
	Revision    int64             `json:"revision"`
	GeneratedAt time.Time         `json:"generated_at"`
	Pass        PassSummary       `json:"pass"`
	Receiver    ReceiverSummary   `json:"receiver"`
	Decoder     DecoderSummary    `json:"decoder"`
	Recording   *RecordingSummary `json:"recording,omitempty"`
	CRCIndex    []CRCEntry        `json:"crc_index"`
	RFPlans     []RFPlanSummary   `json:"rf_plans"`
	AuditEvents []audit.Event     `json:"audit_events"`
	Gaps        []Gap             `json:"gaps"`
	Complete    bool              `json:"complete"`
	Checksum    string            `json:"checksum"`
}

// ComputeChecksum hashes the canonical report content without the checksum field.
func (r Report) ComputeChecksum() string {
	r.Checksum = ""
	data, err := json.Marshal(r)
	if err != nil {
		return ""
	}
	sum := sha256.Sum256(data)
	return hex.EncodeToString(sum[:])
}

// Summary is the list view of a stored report.
type Summary struct {
	ID          string    `json:"id"`
	PassID      string    `json:"pass_id"`
	Revision    int64     `json:"revision"`
	GeneratedAt time.Time `json:"generated_at"`
	Complete    bool      `json:"complete"`
	Gaps        int       `json:"gaps"`
	Checksum    string    `json:"checksum"`
}

func (r Report) Summarize() Summary {
	return Summary{ID: r.ID, PassID: r.PassID, Revision: r.Revision, GeneratedAt: r.GeneratedAt, Complete: r.Complete, Gaps: len(r.Gaps), Checksum: r.Checksum}
}
