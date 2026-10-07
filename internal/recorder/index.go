package recorder

import (
	"encoding/binary"
	"fmt"
	"hash/crc32"
	"os"
)

// FrameIndexEntry describes one framed record located inside a .frames file.
type FrameIndexEntry struct {
	Sequence uint64 `json:"sequence"`
	Epoch    int64  `json:"epoch"`
	Offset   int64  `json:"offset"`
	Size     int    `json:"size"`
	CRC32    uint32 `json:"crc32"`
	CRCValid bool   `json:"crc_valid"`
}

// FrameIndex is the CRC-verified table of contents of a recording segment.
type FrameIndex struct {
	SegmentID       string            `json:"segment_id"`
	FileSize        int64             `json:"file_size"`
	Frames          []FrameIndexEntry `json:"frames"`
	ValidFrames     int               `json:"valid_frames"`
	CorruptFrames   int               `json:"corrupt_frames"`
	MissingSequence []uint64          `json:"missing_sequences,omitempty"`
	Truncated       bool              `json:"truncated"`
	TrailingBytes   int               `json:"trailing_bytes,omitempty"`
}

// FrameIndex scans the durable segment file through the shared frame writer.
func (m *Manager) FrameIndex(segmentID string) (FrameIndex, bool, error) {
	return m.writer.ReadIndex(segmentID)
}

const frameHeaderSize = 28

// ReadIndex scans a segment file, recomputes every CRC and reports gaps.
// A missing segment file is reported as an empty index with present=false.
func (w *FrameWriter) ReadIndex(segmentID string) (index FrameIndex, present bool, err error) {
	data, err := os.ReadFile(w.paths.Recording(segmentID))
	if os.IsNotExist(err) {
		return FrameIndex{SegmentID: segmentID}, false, nil
	}
	if err != nil {
		return FrameIndex{}, false, fmt.Errorf("read recording for index: %w", err)
	}
	return indexFrames(segmentID, data), true, nil
}

func indexFrames(segmentID string, data []byte) FrameIndex {
	index := FrameIndex{SegmentID: segmentID, FileSize: int64(len(data)), Frames: make([]FrameIndexEntry, 0)}
	offset := 0
	for offset < len(data) {
		if len(data)-offset < frameHeaderSize {
			index.Truncated = true
			index.TrailingBytes = len(data) - offset
			break
		}
		header := data[offset : offset+frameHeaderSize]
		sequence := binary.BigEndian.Uint64(header[0:8])
		epoch := int64(binary.BigEndian.Uint64(header[8:16]))
		length := int(binary.BigEndian.Uint64(header[16:24]))
		checksum := binary.BigEndian.Uint32(header[24:28])
		if length <= 0 || offset+frameHeaderSize+length > len(data) {
			index.Truncated = true
			index.TrailingBytes = len(data) - offset
			break
		}
		payload := data[offset+frameHeaderSize : offset+frameHeaderSize+length]
		valid := crc32.ChecksumIEEE(payload) == checksum
		entry := FrameIndexEntry{
			Sequence: sequence, Epoch: epoch, Offset: int64(offset), Size: length,
			CRC32: checksum, CRCValid: valid,
		}
		index.Frames = append(index.Frames, entry)
		if valid {
			index.ValidFrames++
		} else {
			index.CorruptFrames++
		}
		offset += frameHeaderSize + length
	}
	index.MissingSequence = missingSequences(index.Frames)
	return index
}

func missingSequences(frames []FrameIndexEntry) []uint64 {
	if len(frames) == 0 {
		return nil
	}
	var missing []uint64
	expected := frames[0].Sequence
	for _, frame := range frames {
		if frame.Sequence > expected {
			for sequence := expected; sequence < frame.Sequence; sequence++ {
				missing = append(missing, sequence)
			}
		}
		expected = frame.Sequence + 1
	}
	return missing
}
