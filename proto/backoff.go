package proto

// Backoff is the retransmission schedule of RFC 2131 section 4.1.
//
// The RFC's words: "The delay before the first retransmission SHOULD be 4
// seconds randomized by the value of a uniform random number chosen from the
// range -1 to +1. ... The delay before the next retransmission SHOULD be 8
// seconds randomized by the value of a uniform number chosen from the range -1
// to +1. The retransmission delay SHOULD be doubled with subsequent
// retransmissions up to a maximum of 64 seconds."
//
// It is a struct rather than three constants because the same paragraph says
// the delay "SHOULD be chosen to allow sufficient time for replies from the
// server to be delivered based on the characteristics of the internetwork
// between the client and the server", and gives 4/8/64 as an example "in a
// 10Mb/sec Ethernet internetwork". A veth pair inside a network namespace is
// not that internetwork. Configuring this for a test fixture is therefore
// using the RFC's own knob, not weakening a test — and the RFC defaults are
// pinned by their own table test so a change to them is visible.
type Backoff struct {
	// Initial is the delay before the first retransmission, before jitter.
	Initial Duration
	// Max is the ceiling the doubling stops at, before jitter.
	Max Duration
	// Jitter is the half-width of the uniform randomisation applied to every
	// delay: the delay is uniform over [d-Jitter, d+Jitter].
	Jitter Duration
	// MaxRetransmissions is how many retransmissions to make before the
	// transaction is abandoned and the machine reports a typed failure and
	// restarts. Zero means never abandon.
	//
	// The default 4 is the RFC's own worked example, section 3.1(5): "a client
	// retransmitting as described in section 4.1 might retransmit the
	// DHCPREQUEST message four times, for a total delay of 60 seconds, before
	// restarting the initialization procedure."
	MaxRetransmissions int
}

// DefaultBackoff is RFC 2131 section 4.1's example schedule.
func DefaultBackoff() Backoff {
	return Backoff{
		Initial:            4 * Second,
		Max:                64 * Second,
		Jitter:             1 * Second,
		MaxRetransmissions: 4,
	}
}

// Delay returns the delay before retransmission number n, counting the first
// retransmission as n == 0.
//
// The doubling is done by shifting Initial, with the shift count clamped
// before it is applied. Clamping the RESULT instead would be wrong for a
// large n in a way no test on small n can see: 4s << 62 overflows int64 and
// comes back negative, and a negative delay is a timer that fires immediately
// and retransmits in a tight loop.
func (b Backoff) Delay(n int, rnd uint64) Duration {
	if n < 0 {
		n = 0
	}
	d := b.Initial
	if d <= 0 {
		d = 0
	}
	for i := 0; i < n; i++ {
		if b.Max > 0 && d >= b.Max {
			break
		}
		d *= 2
	}
	if b.Max > 0 && d > b.Max {
		d = b.Max
	}
	return jitter(d, b.Jitter, rnd)
}

// Exhausted reports whether retransmission number n is past the budget.
func (b Backoff) Exhausted(n int) bool {
	return b.MaxRetransmissions > 0 && n >= b.MaxRetransmissions
}

// jitter applies a uniform randomisation of +/- half over d, never returning a
// negative delay.
//
// The modulo introduces a bias of at most one part in 2^64 divided by the
// range, which for a range of 2*10^9 is on the order of 10^-10. Named rather
// than hidden: it is not worth a rejection loop, and a rejection loop would
// consume an unbounded number of entropy values per Step, which would break
// the one-rnd-per-Step contract the journal depends on.
func jitter(d, half Duration, rnd uint64) Duration {
	if half <= 0 {
		if d < 0 {
			return 0
		}
		return d
	}
	span := uint64(half)*2 + 1
	off := Duration(rnd%span) - half
	d += off
	if d < 0 {
		return 0
	}
	return d
}

// split derives the i-th independent value from one entropy input.
//
// Step is handed exactly one rnd, because journalling one value per Step is
// what makes replay bit-exact and because a machine that pulled from a
// generator would make replay depend on a call count. Some transitions need
// two unrelated random values (a fresh xid AND a jittered delay), so they are
// derived here by a fixed, pure mixing function of (rnd, i).
//
// This is splitmix64's finalizer. It is used as a mixer, not as a source of
// cryptographic randomness: the entropy comes from the caller.
func split(rnd uint64, i uint64) uint64 {
	z := rnd + 0x9E3779B97F4A7C15*(i+1)
	z = (z ^ (z >> 30)) * 0xBF58476D1CE4E5B9
	z = (z ^ (z >> 27)) * 0x94D049BB133111EB
	return z ^ (z >> 31)
}
