// linedemo/client tags a file, uploads it to the server, then runs repeated
// audit rounds and prints statistics after each.
//
// Usage:
//
//	go run ./cmd/linedemo/client -file /path/to/data [flags]
//	  -protocol      ateniese|erway|sw|bjo|swpub (default ateniese)
//	  -server        server base URL (default http://localhost:8765)
//	  -rounds        audit rounds to run (default 10)
//	  -challenged    blocks challenged per round (default 10; ignored for bjo, which
//	                 fixes its challenge size at tag time via its sentinel encoding)
package main

import (
	"bytes"
	"flag"
	"fmt"
	"io"
	"log"
	"math/big"
	"net/http"
	"os"
	"time"

	"github.com/pinionengineering/storage-proofs/blocks"
	"github.com/pinionengineering/storage-proofs/confidence"
	"github.com/pinionengineering/storage-proofs/line"
	lineAteniese "github.com/pinionengineering/storage-proofs/line/ateniese"
	lineBJO "github.com/pinionengineering/storage-proofs/line/bjo"
	lineErway "github.com/pinionengineering/storage-proofs/line/erway"
	lineSW "github.com/pinionengineering/storage-proofs/line/sw"
	lineSwPub "github.com/pinionengineering/storage-proofs/line/swpub"
	ateniese "github.com/pinionengineering/storage-proofs/pdp/ateniese"
	erway "github.com/pinionengineering/storage-proofs/pdp/erway"
	porbjo "github.com/pinionengineering/storage-proofs/por/bjo"
	porsw "github.com/pinionengineering/storage-proofs/por/sw"
	"github.com/pinionengineering/storage-proofs/suite"
)

const blockSize = 4096

var (
	swPrime, _ = new(big.Int).SetString("340282366920938463463374607431768211507", 10)
	bjoPrime   = big.NewInt(2147483647)
)

var challengerFactories = map[string]line.ChallengerFactory{
	"ateniese": lineAteniese.NewChallengerFactory(),
	"erway":    lineErway.NewChallengerFactory(),
	"sw":       lineSW.NewChallengerFactory(),
	"bjo":      lineBJO.NewChallengerFactory(),
	"swpub":    lineSwPub.NewChallengerFactory(),
}

// setupTagger is what we need from the tagger after TagBlocks.
type setupTagger interface {
	line.Tagger
	line.SetupProducer
}

func main() {
	filePath := flag.String("file", "", "file to audit (required)")
	protocol := flag.String("protocol", "ateniese", "ateniese|erway|sw|bjo")
	server := flag.String("server", "http://localhost:8765", "server base URL")
	rounds := flag.Int("rounds", 10, "audit rounds")
	challenged := flag.Int("challenged", 10, "blocks per challenge (ignored for bjo)")
	flag.Parse()

	if *filePath == "" {
		flag.Usage()
		os.Exit(1)
	}

	s := suite.SuiteV1
	store, err := blocks.OpenFileStore(*filePath, blockSize)
	must(err)
	defer store.Close()

	var (
		tagger setupTagger
		kind   string
	)

	switch *protocol {
	case "ateniese":
		kind = "PDP"
		pk, sk, err := ateniese.KeyGen(128)
		must(err)
		tagger = lineAteniese.NewTagger(pk, sk, s)
		_, err = tagger.TagBlocks(store)
		must(err)

	case "erway":
		kind = "PDP"
		pk, err := erway.KeyGen(128)
		must(err)
		t := lineErway.NewTagger(pk, s)
		_, err = t.TagBlocks(store)
		must(err)
		tagger = t

	case "sw":
		kind = "POR"
		sk, err := porsw.KeyGen(&porsw.Params{S: 10, P: swPrime})
		must(err)
		tagger = lineSW.NewTagger(sk, s)
		_, err = tagger.TagBlocks(store)
		must(err)

	case "bjo":
		kind = "POR"
		mk, err := porbjo.KeyGen(&porbjo.Params{
			V: 5, W: 20, Q: max(*rounds, 10), P: bjoPrime,
			OuterN: 8, OuterK: 4, Alpha: 10, Delta: 0.25,
		})
		must(err)
		tagger = lineBJO.NewTagger(mk, s)
		_, err = tagger.TagBlocks(store)
		must(err)

	case "swpub":
		kind = "POR"
		ps, err := porsw.NewPubScheme(4)
		must(err)
		tagger = lineSwPub.NewTagger(ps, s)
		_, err = tagger.TagBlocks(store)
		must(err)

	default:
		log.Fatalf("unknown protocol %q", *protocol)
	}

	clientSetup, err := tagger.ClientSetup()
	must(err)
	proverSetup, err := tagger.ProverSetup()
	must(err)

	factory := challengerFactories[*protocol]
	challenger, err := factory.NewChallenger(clientSetup, *challenged)
	must(err)

	encoded := tagger.EncodedBlocks()
	nBlocks := store.Len()
	nEncoded := encoded.Len()

	fmt.Printf("protocol: %s (%s)  file: %s  blocks: %d → %d\n",
		*protocol, kind, *filePath, nBlocks, nEncoded)

	must(post(*server+"/file", "application/octet-stream", bytes.NewReader(flattenStore(encoded))))
	fmt.Println("file uploaded")

	must(post(*server+"/setup", "application/json", bytes.NewReader(proverSetup)))
	fmt.Println("setup complete")
	fmt.Println()
	fmt.Printf("%-6s  %-6s  %-10s  %-22s  %-22s\n",
		"Round", "Result", "Latency", "Min-detectable@95%", "Min-detectable@99%")

	n, c := nEncoded, *challenged
	if *protocol == "bjo" {
		n, c = *rounds, 1
	}

	for i := range *rounds {
		t0 := time.Now()
		chal, v, err := challenger.Challenge(encoded.IDs())
		must(err)

		proof, err := requestProof(*server, chal)
		if err != nil {
			log.Fatalf("round %d: %v", i+1, err)
		}

		ok, err := v.Verify(chal, proof)
		must(err)

		result := "OK  "
		if !ok {
			result = "FAIL"
		}
		min95 := confidence.MinDetectableFraction(n, c, i+1, 0.95)
		min99 := confidence.MinDetectableFraction(n, c, i+1, 0.99)
		fmt.Printf("%-6d  %-6s  %-10s  %19.1f%%       %19.1f%%\n",
			i+1, result, time.Since(t0).Round(time.Millisecond), min95*100, min99*100)
		if !ok {
			fmt.Println("        *** server returned an invalid proof ***")
		}
		if i+1 < *rounds {
			time.Sleep(10 * time.Second)
		}
	}
}

func requestProof(server string, chal line.Challenge) (line.Proof, error) {
	resp, err := http.Post(server+"/prove", "application/octet-stream", bytes.NewReader(chal))
	if err != nil {
		return nil, err
	}
	defer resp.Body.Close()
	if resp.StatusCode != http.StatusOK {
		msg, _ := io.ReadAll(resp.Body)
		return nil, fmt.Errorf("/prove %d: %s", resp.StatusCode, msg)
	}
	return io.ReadAll(resp.Body)
}

func post(url, contentType string, body io.Reader) error {
	resp, err := http.Post(url, contentType, body)
	if err != nil {
		return err
	}
	defer resp.Body.Close()
	if resp.StatusCode != http.StatusOK {
		msg, _ := io.ReadAll(resp.Body)
		return fmt.Errorf("POST %s: %d: %s", url, resp.StatusCode, msg)
	}
	return nil
}

func flattenStore(store blocks.BlockStore) []byte {
	var out []byte
	for i := range store.Len() {
		b, err := blocks.BlockAt(store, i)
		if err != nil {
			log.Fatalf("flattenStore: block %d: %v", i, err)
		}
		out = append(out, b...)
	}
	return out
}

func must(err error) {
	if err != nil {
		log.Fatal(err)
	}
}
