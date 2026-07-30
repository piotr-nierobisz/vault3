// Command argon2 is the browser-side Argon2id kernel, compiled to
// WebAssembly. It is not part of the server binary: the wasip1 build tag
// keeps it out of every host build, and nothing in internal/ imports it.
//
// # Why this exists at all
//
// Argon2id is memory-hard on purpose — its cost comes from random access
// across tens of megabytes, which is exactly what JavaScript engines are
// worst at. A pure-JS Argon2id runs roughly an order of magnitude slower
// than native, and the only way to buy that back is to raise the parameters
// on the honest user's device while the attacker's rig pays nothing. So the
// KDF runs as WebAssembly.
//
// Why Go rather than a vendored C or Rust build
//
//   - It is the toolchain this repository already has. There is no npm step
//     here (see claude.md), and adding a C or Rust cross-compiler to build a
//     dependency would be a far larger supply-chain surface than `go build`.
//   - The hashing itself is golang.org/x/crypto/argon2 — the *same* audited
//     implementation internal/crypto uses to hash auth keys server-side.
//     One implementation, two targets: a divergence between what the browser
//     derives and what the server verifies is not expressible.
//   - The build is byte-for-byte reproducible (scripts/build-wasm.sh pins
//     -trimpath and the Go version), so anyone reading this open-source repo
//     can rebuild the artifact and diff its digest against the one the loader
//     pins. That is the whole tamper-evidence story; see web/lib/argon2.ts.
//
// # The ABI
//
// Deliberately tiny — six integers in, one status code out, all data passed
// through one fixed global buffer. A fixed arena means no allocator on the
// boundary and no Go pointer ever escaping to JavaScript, so there is no way
// for a caller to make the module read or write memory it does not own; the
// bounds check below is the entire attack surface. web/lib/argon2.ts mirrors
// these offsets and must be changed in step.
package main

import (
	"unsafe"

	"golang.org/x/crypto/argon2"
)

// Arena layout. Offsets are absolute byte positions within `arena`, which the
// caller locates once via arena_ptr.
const (
	passwordOffset = 0
	passwordMax    = 1024
	saltOffset     = 1024
	saltMax        = 1024
	outputOffset   = 2048
	outputMax      = 1024
	arenaSize      = 4096
)

// Status codes returned by argon2id. Anything non-zero means nothing was
// written to the output region.
const (
	statusOK          = 0
	statusBadLength   = 1
	statusBadCostness = 2
)

var arena [arenaSize]byte

//go:wasmexport arena_ptr
func arenaPtr() unsafe.Pointer { return unsafe.Pointer(&arena[0]) }

// argon2id hashes arena[0:pwLen] with salt arena[1024:1024+saltLen] and
// writes outLen bytes to arena[2048:]. Costs are the standard Argon2
// parameters: time = passes, memoryKiB = memory in KiB, lanes = parallelism.
//
//go:wasmexport argon2id
func argon2id(pwLen, saltLen, time, memoryKiB, lanes, outLen int32) int32 {
	if pwLen < 0 || pwLen > passwordMax ||
		saltLen < 8 || saltLen > saltMax ||
		outLen < 16 || outLen > outputMax {
		return statusBadLength
	}
	// Mirror argon2.IDKey's own preconditions rather than letting it panic:
	// a panic in a wasm reactor traps the whole instance, which the caller
	// can only report as "unlock broken".
	if time < 1 || lanes < 1 || memoryKiB < 8*lanes {
		return statusBadCostness
	}

	key := argon2.IDKey(
		arena[passwordOffset:passwordOffset+pwLen],
		arena[saltOffset:saltOffset+saltLen],
		uint32(time), uint32(memoryKiB), uint8(lanes), uint32(outLen),
	)
	copy(arena[outputOffset:outputOffset+outLen], key)
	for i := range key {
		key[i] = 0
	}
	return statusOK
}

// zeroArena wipes the whole buffer. The caller invokes this once it has
// copied the derived key out, so password-derived material does not linger
// in linear memory for the lifetime of the worker.
//
//go:wasmexport zero_arena
func zeroArena() {
	for i := range arena {
		arena[i] = 0
	}
}

// main is required for a Go main package but never runs: -buildmode=c-shared
// produces a reactor module whose only entry points are the exports above.
func main() {}
