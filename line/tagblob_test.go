package line_test

import (
	"bytes"
	"testing"

	"github.com/pinionengineering/storage-proofs/line"
)

func TestTagBlobRoundTrip(t *testing.T) {
	cases := [][]line.Tag{
		nil,
		{line.Tag("a")},
		{line.Tag("aaa"), line.Tag("b"), line.Tag("ccccc")},
		{line.Tag(""), line.Tag(""), line.Tag("x")},
	}

	for i, tags := range cases {
		blob, err := line.EncodeTagBlob(tags)
		if err != nil {
			t.Fatalf("case %d: encode: %v", i, err)
		}

		decoded, err := line.DecodeTagBlob(blob)
		if err != nil {
			t.Fatalf("case %d: decode: %v", i, err)
		}
		if len(decoded) != len(tags) {
			t.Fatalf("case %d: got %d tags, want %d", i, len(decoded), len(tags))
		}
		for j := range tags {
			if !bytes.Equal(decoded[j], tags[j]) {
				t.Fatalf("case %d: tag %d = %q, want %q", i, j, decoded[j], tags[j])
			}
		}

		// Header-only decode, then per-record range extraction, must match
		// the full decode — this is the actual access pattern a targeted
		// range read uses.
		headerSize := line.TagBlobHeaderSize(len(tags))
		if int64(len(blob)) < headerSize {
			// blob can be shorter than the bound when len(tags) < the
			// caller's assumed max; header-only decode still only needs the
			// blob's own actual header bytes, tested via the full blob below.
		}
		offsets, err := line.DecodeTagBlobHeader(blob)
		if err != nil {
			t.Fatalf("case %d: decode header: %v", i, err)
		}
		if len(offsets) != len(tags) {
			t.Fatalf("case %d: header has %d offsets, want %d", i, len(offsets), len(tags))
		}
		fullHeaderSize := 4 + len(offsets)*8
		for j := range tags {
			start, end := line.TagByteRange(offsets, j)
			got := blob[int64(fullHeaderSize)+start : int64(fullHeaderSize)+end]
			if !bytes.Equal(got, tags[j]) {
				t.Fatalf("case %d: ranged tag %d = %q, want %q", i, j, got, tags[j])
			}
		}
	}
}

// TestTagBlobHeaderSizeOverReadIsSafe confirms the documented contract that
// DecodeTagBlobHeader tolerates being given more bytes than the header
// actually needs — the whole point of TagBlobHeaderSize(maxRecords) being
// usable without first knowing the real record count.
func TestTagBlobHeaderSizeOverReadIsSafe(t *testing.T) {
	tags := []line.Tag{line.Tag("one"), line.Tag("two")}
	blob, err := line.EncodeTagBlob(tags)
	if err != nil {
		t.Fatal(err)
	}

	// Simulate a caller that read TagBlobHeaderSize(1000) bytes even though
	// this blob only has 2 records — pad or truncate as a real ranged read
	// against a short blob would (a real read just returns fewer bytes at
	// EOF, so truncate here rather than pad).
	readSize := line.TagBlobHeaderSize(1000)
	if int64(len(blob)) < readSize {
		readSize = int64(len(blob))
	}
	offsets, err := line.DecodeTagBlobHeader(blob[:readSize])
	if err != nil {
		t.Fatalf("decode over-sized header read: %v", err)
	}
	if len(offsets) != len(tags) {
		t.Fatalf("got %d offsets, want %d", len(offsets), len(tags))
	}
}

func TestDecodeTagBlobHeaderTooShort(t *testing.T) {
	if _, err := line.DecodeTagBlobHeader([]byte{0, 0, 0, 2}); err == nil {
		t.Fatal("expected error decoding a header claiming 2 records with no offset bytes")
	}
}

// TestBlobTagStore drives BlobTagStore against a fetch function that only
// ever serves the exact byte range requested — anything asking for bytes
// outside what was actually written is a bug, not something a real ranged
// blob read would tolerate. Also counts fetches to confirm the header is
// decoded exactly once regardless of how many Tag() calls follow, and that
// each Tag() call after that costs exactly one more range fetch.
func TestBlobTagStore(t *testing.T) {
	tags := []line.Tag{
		line.Tag("alpha"),
		line.Tag("b"),
		line.Tag("gamma-tag"),
		line.Tag(""),
		line.Tag("epsilon"),
	}
	blob, err := line.EncodeTagBlob(tags)
	if err != nil {
		t.Fatal(err)
	}

	const maxRecords = 100 // simulates a caller's own partition-size bound
	fetchCount := 0
	fetch := func(offset, length int64) ([]byte, error) {
		fetchCount++
		if offset < 0 || length < 0 || offset > int64(len(blob)) {
			t.Fatalf("fetch(%d, %d) out of bounds for %d-byte blob", offset, length, len(blob))
		}
		// A real ranged blob read (e.g. gocloud.dev/blob's NewRangeReader)
		// just returns fewer bytes at EOF rather than erroring — the header
		// read deliberately over-reads via TagBlobHeaderSize(maxRecords),
		// which is why this clamps instead of failing.
		end := offset + length
		if end > int64(len(blob)) {
			end = int64(len(blob))
		}
		return blob[offset:end], nil
	}

	store := line.NewBlobTagStore(fetch, maxRecords)

	for i, want := range tags {
		got, err := store.Tag(i)
		if err != nil {
			t.Fatalf("Tag(%d): %v", i, err)
		}
		if !bytes.Equal(got, want) {
			t.Fatalf("Tag(%d) = %q, want %q", i, got, want)
		}
	}

	// One header fetch (cached after the first Tag call) plus one fetch per
	// Tag() call — never more, never re-fetching the header.
	wantFetches := 1 + len(tags)
	if fetchCount != wantFetches {
		t.Fatalf("got %d range fetches for %d Tag() calls, want %d (1 header + 1 per tag)", fetchCount, len(tags), wantFetches)
	}

	if _, err := store.Tag(len(tags)); err == nil {
		t.Fatal("expected an error for an out-of-range index")
	}
	if _, err := store.Tag(-1); err == nil {
		t.Fatal("expected an error for a negative index")
	}
}
