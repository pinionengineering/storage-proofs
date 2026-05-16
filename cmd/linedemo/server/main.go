// linedemo/server stores an uploaded file and responds to audit challenges.
// The file is written once and blocks are read by seeking into it, so you
// can corrupt a specific block offset to watch verification fail.
//
// Usage:
//
//	go run ./cmd/linedemo/server
package main

import (
	"encoding/json"
	"io"
	"log"
	"net/http"
	"os"
	"path/filepath"

	"github.com/pinionengineering/storage-proofs/blocks"
	"github.com/pinionengineering/storage-proofs/line"
	lineAteniese "github.com/pinionengineering/storage-proofs/line/ateniese"
	lineBJO "github.com/pinionengineering/storage-proofs/line/bjo"
	lineErway "github.com/pinionengineering/storage-proofs/line/erway"
	lineSW "github.com/pinionengineering/storage-proofs/line/sw"
	"github.com/pinionengineering/storage-proofs/suite"
)

const (
	addr      = ":8765"
	storeDir  = "linedemo-store"
	blockSize = 4096
)

var proverFactories = map[string]line.ProverFactory{
	"ateniese": lineAteniese.NewProverFactory(),
	"erway":    lineErway.NewProverFactory(suite.SuiteV1),
	"sw":       lineSW.NewProverFactory(),
	"bjo":      lineBJO.NewProverFactory(suite.SuiteV1),
}

type srv struct {
	prover   line.Prover
	dataPath string
}

func main() {
	s := &srv{}
	http.HandleFunc("/file", s.receiveFile)
	http.HandleFunc("/setup", s.setup)
	http.HandleFunc("/prove", s.prove)
	log.Printf("listening on %s", addr)
	log.Fatal(http.ListenAndServe(addr, nil))
}

func (s *srv) receiveFile(w http.ResponseWriter, r *http.Request) {
	if err := os.MkdirAll(storeDir, 0o755); err != nil {
		http.Error(w, err.Error(), http.StatusInternalServerError)
		return
	}
	path := filepath.Join(storeDir, "data")
	f, err := os.Create(path)
	if err != nil {
		http.Error(w, err.Error(), http.StatusInternalServerError)
		return
	}
	defer f.Close()
	n, err := io.Copy(f, r.Body)
	if err != nil {
		http.Error(w, err.Error(), http.StatusInternalServerError)
		return
	}
	s.dataPath = path
	log.Printf("stored %d bytes → %s", n, path)
	log.Printf("to corrupt block i: dd if=/dev/urandom of=%s bs=%d count=1 seek=i conv=notrunc", path, blockSize)
}

func (s *srv) setup(w http.ResponseWriter, r *http.Request) {
	body, err := io.ReadAll(r.Body)
	if err != nil {
		http.Error(w, err.Error(), http.StatusBadRequest)
		return
	}

	var hdr struct {
		Protocol string `json:"protocol"`
	}
	if err := json.Unmarshal(body, &hdr); err != nil {
		http.Error(w, err.Error(), http.StatusBadRequest)
		return
	}

	factory, ok := proverFactories[hdr.Protocol]
	if !ok {
		http.Error(w, "unknown protocol: "+hdr.Protocol, http.StatusBadRequest)
		return
	}

	if err := os.WriteFile(filepath.Join(storeDir, "setup.json"), body, 0o644); err != nil {
		http.Error(w, err.Error(), http.StatusInternalServerError)
		return
	}

	store, err := blocks.OpenFileStore(s.dataPath, blockSize)
	if err != nil {
		http.Error(w, err.Error(), http.StatusInternalServerError)
		return
	}
	defer store.Close()

	prover, err := factory.NewProver(body, store)
	if err != nil {
		http.Error(w, err.Error(), http.StatusInternalServerError)
		return
	}
	s.prover = prover
	log.Printf("%s prover ready", hdr.Protocol)
}

func (s *srv) prove(w http.ResponseWriter, r *http.Request) {
	if s.prover == nil || s.dataPath == "" {
		http.Error(w, "not set up", http.StatusServiceUnavailable)
		return
	}
	chalBytes, err := io.ReadAll(r.Body)
	if err != nil {
		http.Error(w, err.Error(), http.StatusBadRequest)
		return
	}

	store, err := blocks.OpenFileStore(s.dataPath, blockSize)
	if err != nil {
		http.Error(w, err.Error(), http.StatusInternalServerError)
		return
	}
	defer store.Close()

	proof, err := s.prover.Prove(line.Challenge(chalBytes), store)
	if err != nil {
		http.Error(w, err.Error(), http.StatusInternalServerError)
		return
	}
	w.Header().Set("Content-Type", "application/octet-stream")
	w.Write(proof)
}

