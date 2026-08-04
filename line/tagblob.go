package line

import (
	"encoding/binary"
	"fmt"
)

// TagBlobHeaderSize returns the number of bytes needed to safely read a
// TagBlob's header when the record count is bounded by maxRecords (e.g. a
// caller's own partition-size cap). Reading this many bytes is always
// sufficient for DecodeTagBlobHeader to succeed in a single ranged read,
// without first needing a separate round trip to discover the actual record
// count.
func TagBlobHeaderSize(maxRecords int) int64 {
	return 4 + int64(maxRecords)*8
}

// EncodeTagBlob serializes tags into a record-oriented binary blob:
//
//	[4-byte BE record count N]
//	[N x 8-byte BE cumulative end-offset, relative to the start of the data
//	 section that follows the header]
//	[tag[0] bytes || tag[1] bytes || ... || tag[N-1] bytes]
//
// A fixed-position header plus an explicit offset table means any single
// tag's byte range is known from the header alone, without every tag needing
// to be the same length — line.Tag is opaque and protocol-dependent (sw and
// swpub tags are fixed-width G1 points; ateniese tags are variable-length
// JSON) — so a caller who only needs tag i can range-read the header, then
// range-read exactly [start,end) for that one tag, instead of downloading
// every tag in the blob. Mirrors ipfs-storage-proofs/manifest_binary.go's
// fixed-width-record approach, generalized to variable-length records via an
// offset table instead of padding every record to a fixed size.
func EncodeTagBlob(tags []Tag) ([]byte, error) {
	n := len(tags)
	if n > 1<<32-1 {
		return nil, fmt.Errorf("line: EncodeTagBlob: %d records exceeds uint32 range", n)
	}
	headerSize := 4 + n*8
	dataSize := 0
	for _, t := range tags {
		dataSize += len(t)
	}
	out := make([]byte, headerSize+dataSize)
	binary.BigEndian.PutUint32(out[0:4], uint32(n))
	cum := int64(0)
	dataOff := headerSize
	for i, t := range tags {
		cum += int64(len(t))
		binary.BigEndian.PutUint64(out[4+i*8:4+i*8+8], uint64(cum))
		copy(out[dataOff:dataOff+len(t)], t)
		dataOff += len(t)
	}
	return out, nil
}

// DecodeTagBlobHeader parses just a TagBlob's header — record count and the
// cumulative end-offset table — from data, which must contain at least the
// header's own bytes (4 + recordCount*8; see TagBlobHeaderSize for how a
// caller bounds this without knowing recordCount in advance). Trailing bytes
// beyond the header (i.e. tag data) are ignored, so it's safe to pass a
// TagBlobHeaderSize(maxRecords)-sized ranged read directly even when the
// blob's actual record count is smaller than maxRecords.
//
// Returns offsets, where offsets[i] is tag i's end offset within the data
// section (tag i's start is offsets[i-1], or 0 for i==0) — pass to
// TagByteRange to get one tag's [start,end) range.
func DecodeTagBlobHeader(data []byte) (offsets []int64, err error) {
	if len(data) < 4 {
		return nil, fmt.Errorf("line: DecodeTagBlobHeader: %d bytes, need at least 4", len(data))
	}
	n := int(binary.BigEndian.Uint32(data[0:4]))
	need := 4 + n*8
	if len(data) < need {
		return nil, fmt.Errorf("line: DecodeTagBlobHeader: %d records need %d header bytes, got %d", n, need, len(data))
	}
	offsets = make([]int64, n)
	for i := range offsets {
		offsets[i] = int64(binary.BigEndian.Uint64(data[4+i*8 : 4+i*8+8]))
	}
	return offsets, nil
}

// TagByteRange returns tag i's [start,end) byte range within the data
// section that follows a TagBlob's header (i.e. relative to the header's own
// end). A caller doing a ranged blob read adds the header length —
// 4+len(offsets)*8, or TagBlobHeaderSize(maxRecords) if that's how many
// header bytes it read — to get absolute offsets into the blob.
func TagByteRange(offsets []int64, i int) (start, end int64) {
	if i == 0 {
		return 0, offsets[0]
	}
	return offsets[i-1], offsets[i]
}

// DecodeTagBlob fully decodes a TagBlob produced by EncodeTagBlob. For
// callers that already have the whole blob in hand (e.g. rewriting a
// partition's tags-so-far at a checkpoint) rather than doing a targeted range
// read for one tag. Decoded tags alias data rather than copying it.
func DecodeTagBlob(data []byte) ([]Tag, error) {
	offsets, err := DecodeTagBlobHeader(data)
	if err != nil {
		return nil, err
	}
	headerSize := 4 + len(offsets)*8
	tags := make([]Tag, len(offsets))
	for i := range tags {
		start, end := TagByteRange(offsets, i)
		if headerSize+int(end) > len(data) {
			return nil, fmt.Errorf("line: DecodeTagBlob: record %d end %d exceeds data length %d", i, headerSize+int(end), len(data))
		}
		tags[i] = Tag(data[headerSize+int(start) : headerSize+int(end)])
	}
	return tags, nil
}

// RangeFetcher fetches the byte range [offset, offset+length) of a stored
// TagBlob — the shape gocloud.dev/blob's Bucket.NewRangeReader already takes,
// so a caller backed by GCS (or any other blob.Bucket driver) can implement
// this as a thin wrapper with no format-specific logic of its own.
type RangeFetcher func(offset, length int64) ([]byte, error)

// BlobTagStore implements TagStore over a TagBlob without ever holding more
// than one record's bytes plus the header at a time. The header (bounded by
// maxRecords, via TagBlobHeaderSize — the caller's own partition-size cap,
// so this is always a small, single range read) is fetched and decoded once,
// lazily, on the first Tag call, and cached; every Tag(i) after that is one
// more targeted range read for exactly that record.
type BlobTagStore struct {
	fetch      RangeFetcher
	maxRecords int
	offsets    []int64 // decoded header, cached after the first Tag call
	headerSize int64
}

// NewBlobTagStore returns a BlobTagStore that reads from fetch. maxRecords
// bounds the blob's record count (e.g. the partition size it was written
// with) — see TagBlobHeaderSize.
func NewBlobTagStore(fetch RangeFetcher, maxRecords int) *BlobTagStore {
	return &BlobTagStore{fetch: fetch, maxRecords: maxRecords}
}

func (s *BlobTagStore) ensureHeader() error {
	if s.offsets != nil {
		return nil
	}
	headerData, err := s.fetch(0, TagBlobHeaderSize(s.maxRecords))
	if err != nil {
		return fmt.Errorf("line: BlobTagStore: fetch header: %w", err)
	}
	offsets, err := DecodeTagBlobHeader(headerData)
	if err != nil {
		return fmt.Errorf("line: BlobTagStore: decode header: %w", err)
	}
	s.offsets = offsets
	s.headerSize = int64(4 + len(offsets)*8)
	return nil
}

// Tag implements TagStore.
func (s *BlobTagStore) Tag(i int) (Tag, error) {
	if err := s.ensureHeader(); err != nil {
		return nil, err
	}
	if i < 0 || i >= len(s.offsets) {
		return nil, fmt.Errorf("line: BlobTagStore: index %d out of range [0, %d)", i, len(s.offsets))
	}
	start, end := TagByteRange(s.offsets, i)
	data, err := s.fetch(s.headerSize+start, end-start)
	if err != nil {
		return nil, fmt.Errorf("line: BlobTagStore: fetch tag %d: %w", i, err)
	}
	return Tag(data), nil
}
