package sw

// tagsMap converts a dense, index-0..N-1 tag slice (as produced by
// TagBlocks) into the index-keyed map RespondFetch/Respond now take. Tests
// exercise the honest, full-coverage case, so the map here always covers
// every index — RespondFetch itself only ever reads the challenged subset.
func tagsMap(tags []*Tag) map[int]*Tag {
	m := make(map[int]*Tag, len(tags))
	for i, t := range tags {
		m[i] = t
	}
	return m
}

// rawTagsMap is tagsMap's counterpart for PrivScheme/PubScheme.RespondFetch,
// which take serialized tags ([][]byte) rather than the decoded *Tag type.
func rawTagsMap(tags [][]byte) map[int][]byte {
	m := make(map[int][]byte, len(tags))
	for i, t := range tags {
		m[i] = t
	}
	return m
}
