package blocks

import "fmt"

// MapStore is a BlockStore with caller-supplied identifiers.
// Unlike MemStore (which uses IntID(i) for all IDs), MapStore preserves
// whatever identifiers the caller provides, enabling non-sequential or
// arbitrary-byte block addressing.
type MapStore struct {
	ids  [][]byte
	data map[string][]byte
}

// NewMapStore constructs a MapStore from parallel slices of identifiers and
// block data. ids[i] is the identifier for data[i].
func NewMapStore(ids, data [][]byte) (*MapStore, error) {
	if len(ids) != len(data) {
		return nil, fmt.Errorf("blocks.NewMapStore: ids len %d != data len %d", len(ids), len(data))
	}
	m := &MapStore{
		ids:  make([][]byte, len(ids)),
		data: make(map[string][]byte, len(ids)),
	}
	for i, id := range ids {
		m.ids[i] = id
		m.data[string(id)] = data[i]
	}
	return m, nil
}

func (s *MapStore) Len() int      { return len(s.ids) }
func (s *MapStore) IDs() [][]byte { return s.ids }

func (s *MapStore) Block(id []byte) ([]byte, error) {
	b, ok := s.data[string(id)]
	if !ok {
		return nil, fmt.Errorf("blocks: id %x not found", id)
	}
	return b, nil
}

func (s *MapStore) SetBlock(id []byte, data []byte) error {
	if _, exists := s.data[string(id)]; !exists {
		s.ids = append(s.ids, id)
	}
	s.data[string(id)] = data
	return nil
}
