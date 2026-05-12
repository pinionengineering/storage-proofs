.PHONY: all build test stats clean

all: build

build:
	go build ./...

test:
	go test ./...

storagecharts: $(shell find cmd/storagecharts por pdp -name '*.go')
	go build -o storagecharts ./cmd/storagecharts

storagestats: $(shell find cmd/storagestats por pdp -name '*.go')
	go build -o storagestats ./cmd/storagestats

proofbench: $(shell find cmd/proofbench por pdp -name '*.go')
	go build -o proofbench ./cmd/proofbench

storage_proof_charts.html: storagecharts
	./storagecharts

comparison.html: proofbench
	./proofbench

stats: storagestats
	./storagestats

clean:
	rm -f storagecharts storagestats proofbench
	rm -f storage_proof_charts.html comparison.html
