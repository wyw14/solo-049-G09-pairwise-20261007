package recorder

import (
	"encoding/binary"
	"os"
	"path/filepath"
	"testing"

	"orbitlink/internal/store"
)

func newTestWriter(t *testing.T) (*FrameWriter, store.Paths) {
	t.Helper()
	paths := store.NewPaths(t.TempDir())
	return NewFrameWriter(paths), paths
}

func TestFrameIndexVerifiesHealthyRecording(t *testing.T) {
	writer, paths := newTestWriter(t)
	for sequence := uint64(1); sequence <= 3; sequence++ {
		frame := Frame{Sequence: sequence, Epoch: 2, Payload: []byte{byte(sequence), 2, 3, 4}}
		if err := writer.Append("seg-1", frame); err != nil {
			t.Fatal(err)
		}
	}
	index, present, err := writer.ReadIndex("seg-1")
	if err != nil || !present {
		t.Fatalf("index missing: present=%v err=%v", present, err)
	}
	if index.ValidFrames != 3 || index.CorruptFrames != 0 || index.Truncated {
		t.Fatalf("unexpected index: %+v", index)
	}
	if len(index.MissingSequence) != 0 || index.FileSize == 0 {
		t.Fatalf("unexpected gaps or size: %+v", index)
	}
	if _, present, err := writer.ReadIndex("absent"); err != nil || present {
		t.Fatalf("absent file should be present=false: %v %v", present, err)
	}
	_ = paths
}

func TestFrameIndexFlagsCorruptAndMissingSequences(t *testing.T) {
	writer, paths := newTestWriter(t)
	path := paths.Recording("seg-bad")
	if err := os.MkdirAll(filepath.Dir(path), 0o755); err != nil {
		t.Fatal(err)
	}
	var raw []byte
	appendRecord := func(sequence uint64, payload []byte, checksum uint32) {
		header := make([]byte, frameHeaderSize)
		binary.BigEndian.PutUint64(header[0:8], sequence)
		binary.BigEndian.PutUint64(header[8:16], 2)
		binary.BigEndian.PutUint64(header[16:24], uint64(len(payload)))
		binary.BigEndian.PutUint32(header[24:28], checksum)
		raw = append(raw, header...)
		raw = append(raw, payload...)
	}
	// Sequence 5 then 8, both carrying deliberately wrong checksums.
	appendRecord(5, []byte{1, 2, 3, 4}, 0xdeadbeef)
	appendRecord(8, []byte{5, 6, 7, 8}, 0x0badc0de)
	if err := os.WriteFile(path, raw, 0o644); err != nil {
		t.Fatal(err)
	}
	index, _, err := writer.ReadIndex("seg-bad")
	if err != nil {
		t.Fatal(err)
	}
	if index.CorruptFrames != 2 || index.ValidFrames != 0 {
		t.Fatalf("expected two corrupt frames: %+v", index)
	}
	if len(index.MissingSequence) != 2 || index.MissingSequence[0] != 6 || index.MissingSequence[1] != 7 {
		t.Fatalf("expected missing sequences 6 and 7: %+v", index.MissingSequence)
	}
}

func TestFrameIndexFlagsTruncatedTrailingBytes(t *testing.T) {
	writer, paths := newTestWriter(t)
	path := paths.Recording("seg-trunc")
	if err := os.MkdirAll(filepath.Dir(path), 0o755); err != nil {
		t.Fatal(err)
	}
	header := make([]byte, frameHeaderSize)
	binary.BigEndian.PutUint64(header[16:24], 100) // claims 100 payload bytes
	header = append(header, 1, 2, 3, 4)            // only 4 arrive
	if err := os.WriteFile(path, header, 0o644); err != nil {
		t.Fatal(err)
	}
	index, _, err := writer.ReadIndex("seg-trunc")
	if err != nil {
		t.Fatal(err)
	}
	if !index.Truncated || index.TrailingBytes != frameHeaderSize+4 {
		t.Fatalf("expected truncation marker: %+v", index)
	}
}
