package ateniese

import "fmt"

// tagsMap converts a dense, index-0..N-1 tag slice into the TagFetcher
// closure GenProof now takes. Tests exercise the honest, full-coverage case,
// so the backing map here always covers every index — GenProof itself only
// ever calls the fetcher for the challenged subset (the c positions named by
// chal.K1's permutation).
func tagsMap(tags []*Tag) TagFetcher {
	m := make(map[int]*Tag, len(tags))
	for i, t := range tags {
		m[i] = t
	}
	return func(i int) (*Tag, error) {
		t, ok := m[i]
		if !ok {
			return nil, fmt.Errorf("tagsMap: no tag for index %d", i)
		}
		return t, nil
	}
}
