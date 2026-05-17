.PHONY: all build test study docs clean

DOCS = docs

all: build

build:
	go build ./...

test:
	go test ./...

study: $(shell find cmd/study por pdp line blocks suite -name '*.go') cmd/study/study.tmpl
	go build -o study ./cmd/study
	./study
	mkdir -p $(DOCS)
	cp study.html $(DOCS)/study.html

docs: study

clean:
	rm -f study study.html
