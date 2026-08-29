package runtime

import (
	"crypto/rand"
	"encoding/binary"
	"sync"
)

// Entropy is the real source of the rnd value each Step consumes.
//
// crypto/rand seeds it; a splitmix64 generator produces the stream. Not
// math/rand: the transaction id derives from this, and RFC 2131 section 4.1
// requires a client to "choose" an xid that a server uses to match responses,
// which an attacker who can predict it can forge. Not crypto/rand per call
// either — the machine consumes a value on EVERY Step, including ones that use
// it for nothing, and a syscall per timer fire is a cost with no return.
//
// A seed failure is fatal by design. Continuing with a predictable stream would
// mean a client whose xids can be guessed, which is worse than not starting.
type Entropy struct {
	mu    sync.Mutex
	state uint64
}

// NewEntropy seeds from crypto/rand.
func NewEntropy() (*Entropy, error) {
	var b [8]byte
	if _, err := rand.Read(b[:]); err != nil {
		return nil, err
	}
	return &Entropy{state: binary.BigEndian.Uint64(b[:])}, nil
}

// NewEntropySeeded returns a deterministic source. It exists for replay and for
// tests, and it is exported rather than test-only because a replay of a
// recorded journal is a production feature (requirement G6), not a test
// fixture.
func NewEntropySeeded(seed uint64) *Entropy { return &Entropy{state: seed} }

// Uint64 returns the next value.
func (e *Entropy) Uint64() uint64 {
	e.mu.Lock()
	defer e.mu.Unlock()
	e.state += 0x9E3779B97F4A7C15
	z := e.state
	z = (z ^ (z >> 30)) * 0xBF58476D1CE4E5B9
	z = (z ^ (z >> 27)) * 0x94D049BB133111EB
	return z ^ (z >> 31)
}
