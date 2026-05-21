// Package blocks defines the BlockStore interface for indexed access to a
// sequence of fixed-size blocks, along with two standard implementations:
// FileStore (disk-backed) and MemStore (in-memory).
package blocks

import (
	"encoding/binary"
	"fmt"
	"io"
	"os"
)

// BlockStore provides keyed read/write access to a sequence of blocks.
// IDs()[i] is the identifier for block i; len(IDs()) == Len().
type BlockStore interface {
	// Len returns the number of blocks.
	Len() int
	// IDs returns the identifier for each block, in order.
	IDs() [][]byte
	// Block returns the bytes of the block with the given id.
	Block(id []byte) ([]byte, error)
	// SetBlock writes data as the block with the given id, growing the store if needed.
	SetBlock(id []byte, data []byte) error
}

// IntID encodes an integer index as a big-endian uint64 byte slice.
func IntID(i int) []byte {
	var buf [8]byte
	binary.BigEndian.PutUint64(buf[:], uint64(i))
	return buf[:]
}

// IDInt decodes the last 8 bytes of id as a big-endian uint64 integer index.
func IDInt(id []byte) int {
	if len(id) < 8 {
		return 0
	}
	return int(binary.BigEndian.Uint64(id[len(id)-8:]))
}

// BlockAt returns the bytes of the block at position idx in store.IDs().
// This encodes the canonical contract between IDs() and Block(): to fetch
// block i, look up its identifier via IDs()[i] and pass it to Block.
func BlockAt(store BlockStore, idx int) ([]byte, error) {
	return store.Block(store.IDs()[idx])
}

// ---------------------------------------------------------------------------
// FileStore
// ---------------------------------------------------------------------------

// FileStore is a BlockStore backed by a file. Blocks are stored at fixed
// offsets: block i occupies bytes [i*blockSize, (i+1)*blockSize).
// The last block may be shorter than blockSize.
type FileStore struct {
	f         *os.File
	blockSize int
	n         int // cached block count
}

// NewFileStore wraps an already-open file. blockSize is the size of each block
// in bytes. The block count is derived from the current file size.
func NewFileStore(f *os.File, blockSize int) (*FileStore, error) {
	if blockSize <= 0 {
		return nil, fmt.Errorf("blocks: blockSize must be positive")
	}
	info, err := f.Stat()
	if err != nil {
		return nil, fmt.Errorf("blocks: stat: %w", err)
	}
	n := 0
	if info.Size() > 0 {
		n = int((info.Size() + int64(blockSize) - 1) / int64(blockSize))
	}
	return &FileStore{f: f, blockSize: blockSize, n: n}, nil
}

// OpenFileStore opens an existing file for reading and writing.
func OpenFileStore(path string, blockSize int) (*FileStore, error) {
	f, err := os.OpenFile(path, os.O_RDWR, 0o644)
	if err != nil {
		return nil, fmt.Errorf("blocks: open %s: %w", path, err)
	}
	return NewFileStore(f, blockSize)
}

// CreateFileStore creates or truncates a file for writing.
func CreateFileStore(path string, blockSize int) (*FileStore, error) {
	f, err := os.Create(path)
	if err != nil {
		return nil, fmt.Errorf("blocks: create %s: %w", path, err)
	}
	return NewFileStore(f, blockSize)
}

// BlockSize returns the fixed block size for this store.
func (s *FileStore) BlockSize() int { return s.blockSize }

// File returns the underlying file.
func (s *FileStore) File() *os.File { return s.f }

// Close closes the underlying file.
func (s *FileStore) Close() error { return s.f.Close() }

func (s *FileStore) Len() int { return s.n }

func (s *FileStore) IDs() [][]byte {
	ids := make([][]byte, s.n)
	for i := range s.n {
		ids[i] = IntID(i)
	}
	return ids
}

func (s *FileStore) Block(id []byte) ([]byte, error) {
	i := IDInt(id)
	if i < 0 || i >= s.n {
		return nil, fmt.Errorf("blocks: index %d out of range [0, %d)", i, s.n)
	}
	buf := make([]byte, s.blockSize)
	n, err := s.f.ReadAt(buf, int64(i)*int64(s.blockSize))
	if err == io.EOF {
		err = nil
	}
	if err != nil {
		return nil, fmt.Errorf("blocks: read block %d: %w", i, err)
	}
	return buf[:n], nil
}

func (s *FileStore) SetBlock(id []byte, data []byte) error {
	i := IDInt(id)
	if i < 0 {
		return fmt.Errorf("blocks: negative index %d", i)
	}
	if _, err := s.f.WriteAt(data, int64(i)*int64(s.blockSize)); err != nil {
		return fmt.Errorf("blocks: write block %d: %w", i, err)
	}
	if i >= s.n {
		s.n = i + 1
	}
	return nil
}

// ---------------------------------------------------------------------------
// MemStore
// ---------------------------------------------------------------------------

// MemStore is a BlockStore backed by a slice of byte slices.
// It is useful for testing and for protocols that produce an in-memory encoded
// file (e.g. BJO) before transferring it to a FileStore.
type MemStore struct {
	blocks [][]byte
}

// NewMemStore wraps an existing slice of blocks. The slice is not copied;
// callers should not modify it after construction.
func NewMemStore(blocks [][]byte) *MemStore {
	return &MemStore{blocks: blocks}
}

func (s *MemStore) Len() int { return len(s.blocks) }

func (s *MemStore) IDs() [][]byte {
	ids := make([][]byte, len(s.blocks))
	for i := range s.blocks {
		ids[i] = IntID(i)
	}
	return ids
}

func (s *MemStore) Block(id []byte) ([]byte, error) {
	i := IDInt(id)
	if i < 0 || i >= len(s.blocks) {
		return nil, fmt.Errorf("blocks: index %d out of range [0, %d)", i, len(s.blocks))
	}
	return s.blocks[i], nil
}

func (s *MemStore) SetBlock(id []byte, data []byte) error {
	i := IDInt(id)
	if i < 0 {
		return fmt.Errorf("blocks: negative index %d", i)
	}
	if i >= len(s.blocks) {
		grown := make([][]byte, i+1)
		copy(grown, s.blocks)
		s.blocks = grown
	}
	s.blocks[i] = data
	return nil
}

// Blocks returns the underlying slice.
func (s *MemStore) Blocks() [][]byte { return s.blocks }
