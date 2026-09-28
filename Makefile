.PHONY: lint release release-snapshot test clean

lint:
	@UNF=$$(gofmt -l .); if [ -n "$$UNF" ]; then echo "unformatted:"; echo "$$UNF"; exit 1; fi
	go vet ./...

test:
	go test ./...

release:
	goreleaser release --clean

release-snapshot:
	goreleaser build --snapshot --clean

clean:
	rm -rf dist/
