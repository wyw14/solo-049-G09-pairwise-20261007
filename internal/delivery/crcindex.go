package delivery

import (
	"crypto/sha256"
	"encoding/binary"
	"encoding/hex"
	"errors"
	"fmt"
	"hash/crc32"
	"io"
	"os"
)

// frameHeaderSize mirrors recorder.FrameWriter: sequence, epoch, length, crc32.
const frameHeaderSize = 28

type frameScan struct {
	entries  []CRCEntry
	bytes    int64
	checksum string
	gaps     []Gap
}

// scanFrames reads a recording file, verifies every frame CRC and reports
// sequence discontinuities, checksum mismatches and truncated tails as gaps.
func scanFrames(path string) (frameScan, error) {
	scan := frameScan{entries: []CRCEntry{}}
	file, err := os.Open(path)
	if errors.Is(err, os.ErrNotExist) {
		return scan, nil
	}
	if err != nil {
		return scan, fmt.Errorf("open recording: %w", err)
	}
	defer file.Close()
	digester := sha256.New()
	reader := io.TeeReader(file, digester)
	header := make([]byte, frameHeaderSize)
	var previous uint64
	for index := 0; ; index++ {
		if _, err := io.ReadFull(reader, header); err != nil {
			if err == io.EOF {
				break
			}
			if err == io.ErrUnexpectedEOF {
				scan.gaps = append(scan.gaps, Gap{Code: "frames.truncated", Detail: "recording ends with a partial frame header"})
				break
			}
			return scan, fmt.Errorf("read frame header: %w", err)
		}
		sequence := binary.BigEndian.Uint64(header[0:8])
		epoch := int64(binary.BigEndian.Uint64(header[8:16]))
		length := binary.BigEndian.Uint64(header[16:24])
		crc := binary.BigEndian.Uint32(header[24:28])
		if length > 1<<20 {
			return scan, fmt.Errorf("frame %d length %d exceeds decoder limits", sequence, length)
		}
		payload := make([]byte, length)
		if _, err := io.ReadFull(reader, payload); err != nil {
			if err == io.EOF || err == io.ErrUnexpectedEOF {
				scan.gaps = append(scan.gaps, Gap{Code: "frames.truncated", Detail: fmt.Sprintf("frame %d payload is incomplete", sequence)})
				break
			}
			return scan, fmt.Errorf("read frame %d payload: %w", sequence, err)
		}
		if crc32.ChecksumIEEE(payload) != crc {
			scan.gaps = append(scan.gaps, Gap{Code: "frames.crc-mismatch", Detail: fmt.Sprintf("frame %d payload fails its CRC32", sequence)})
		}
		if index > 0 && sequence != previous+1 {
			scan.gaps = append(scan.gaps, Gap{Code: "frames.sequence-gap", Detail: fmt.Sprintf("sequence jumps from %d to %d", previous, sequence)})
		}
		previous = sequence
		scan.entries = append(scan.entries, CRCEntry{Sequence: sequence, Epoch: epoch, CRC32: crc})
	}
	info, err := file.Stat()
	if err != nil {
		return scan, fmt.Errorf("stat recording: %w", err)
	}
	scan.bytes = info.Size()
	scan.checksum = hex.EncodeToString(digester.Sum(nil))
	return scan, nil
}
