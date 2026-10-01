// Copyright (c) 2026 Christian Kamien. MIT License, see LICENSE.

package proto

import (
	"github.com/claymore666/dhcp-golib/wire"
)

// RapidCommit6Counters is what this machine did with DHCPv6 Replies carrying
// option 14. Accepted is a lease taken with no Request; Refused is a Reply+14
// that gave no lease, whether a rule turned it away or it answered the Solicit
// with a refusal. Every refusal also writes its own journal line
// (claymore666/docker-net-dhcp#926).
type RapidCommit6Counters struct {
	Accepted uint64
	Refused  uint64
}

// RapidCommitCounters returns the counters as a copy
// (claymore666/docker-net-dhcp#926).
func (m *Machine6) RapidCommitCounters() RapidCommit6Counters { return m.rapidCounts }

// hasRapidOption6 reports whether the message carries option 14 in any form,
// malformed included: a Reply with the option is never treated as a plain one
// (claymore666/docker-net-dhcp#926).
func hasRapidOption6(msg *wire.MessageV6) bool {
	return msg != nil && msg.Type == wire.MsgReply && msg.Options.Count(wire.OptV6RapidCommit) > 0
}

// countRapidDiscard counts a Reply+14 a rule other than the rapid ones dropped:
// admit, or a state with no exchange in flight (claymore666/docker-net-dhcp#926).
func (m *Machine6) countRapidDiscard(msg *wire.MessageV6) {
	if hasRapidOption6(msg) {
		m.rapidCounts.Refused++
	}
}

func (m *Machine6) refuseRapid6(out *actions, why string) {
	m.rapidCounts.Refused++
	out.journal(m, "Reply with Rapid Commit in "+m.state.String()+": refused, "+why)
}

// takeRapidReply handles a Reply in SELECTING that admit has passed. RFC 8415
// section 18.2.1: a client that sent option 14 takes a Reply carrying it as the
// answer to its Solicit, and "will discard any Reply messages that do not
// contain the Rapid Commit option" (claymore666/docker-net-dhcp#926).
func (m *Machine6) takeRapidReply(now Instant, rnd uint64, msg *wire.MessageV6, out *actions) {
	has, err := msg.Options.RapidCommit()
	switch {
	case err != nil:
		m.refuseRapid6(out, "option 14 is malformed")
		return
	case !has && !m.params.RapidCommit:
		out.journal(m, "a Reply arrived while soliciting: ignored")
		return
	case !has:
		out.journal(m, "a Reply without Rapid Commit arrived while soliciting: discarded (§18.2.1)")
		return
	case !m.params.RapidCommit:
		m.refuseRapid6(out, "the Solicit did not ask for it")
		return
	}
	m.takeReply(now, rnd, msg, out)
	if m.state == State6DAD || m.state == State6Bound {
		m.rapidCounts.Accepted++
		out.journal(m, "Reply with Rapid Commit: lease taken, no Request sent")
		return
	}
	m.rapidCounts.Refused++
	out.journal(m, "Reply with Rapid Commit: no lease taken")
}

// rejectRapidHint stops a restarted Solicit from asking again for the address
// a Reply+14 just said is not on this link: the hinted Solicit with option 14
// is answered at once, so the same hint would loop at the Solicit delay. It is
// the machine's own memory and is not persisted; a restarted client asks once
// more and is told again (claymore666/docker-net-dhcp#926).
func (m *Machine6) rejectRapidHint() {
	if h := m.solicitHint(); h.IsValid() {
		m.hintOffLink = h
	}
}
