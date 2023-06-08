module github.com/decred/dcrd/connmgr/v3

go 1.17

require (
	github.com/decred/dcrd/addrmgr/v2 v2.0.0-00010101000000-000000000000
	github.com/decred/dcrd/wire v1.6.0
	github.com/decred/slog v1.2.0
)

replace github.com/decred/dcrd/addrmgr/v2 => ../addrmgr

require (
	github.com/decred/dcrd/chaincfg/chainhash v1.0.4 // indirect
	github.com/decred/dcrd/crypto/blake256 v1.0.1 // indirect
	github.com/klauspost/cpuid/v2 v2.0.9 // indirect
	golang.org/x/crypto v0.9.0 // indirect
	golang.org/x/sys v0.8.0 // indirect
	lukechampine.com/blake3 v1.2.1 // indirect
)
