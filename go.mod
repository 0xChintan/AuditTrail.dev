module audittrail.dev

go 1.26.5

require (
	github.com/digitorus/timestamp v0.0.0-20250524132541-c45532741eea
	github.com/go-pdf/fpdf v0.9.0
	github.com/gowebpki/jcs v1.0.2
	github.com/jackc/pgx/v5 v5.11.0
	golang.org/x/time v0.16.0
)

require (
	github.com/digitorus/pkcs7 v0.0.0-20230713084857-e76b763bdc49 // indirect
	github.com/jackc/pgpassfile v1.0.0 // indirect
	github.com/jackc/pgservicefile v0.0.0-20240606120523-5a60cdf6a761 // indirect
	github.com/jackc/puddle/v2 v2.2.2 // indirect
	golang.org/x/sync v0.17.0 // indirect
	golang.org/x/text v0.29.0 // indirect
)

// The repo root is the Go module so `go build ./...` works from a clean
// clone; JS/TS trees are skipped.
ignore (
	./apps
	./packages/core
	./packages/mcp-sidecar
	./packages/sdk
	node_modules
)
