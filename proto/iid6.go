// Copyright (c) 2026 Christian Kamien. MIT License, see LICENSE.

package proto

import (
	"crypto/sha256"
	"encoding/binary"
	"errors"
	"fmt"
	"net/netip"
)

// IIDMode is how a SLAAC address's interface identifier is formed (dhcp-golib#54).
type IIDMode uint8

// The two identifiers (dhcp-golib#54).
const (
	// IIDModeEUI64 is RFC 4291 Appendix A's modified EUI-64 from Params6.LinkAddr (dhcp-golib#54).
	IIDModeEUI64 IIDMode = iota
	// IIDModeStablePrivacy is RFC 7217's stable, semantically opaque identifier (dhcp-golib#54).
	IIDModeStablePrivacy
)

func (m IIDMode) String() string {
	switch m {
	case IIDModeEUI64:
		return "eui64"
	case IIDModeStablePrivacy:
		return "stable-privacy"
	default:
		return fmt.Sprintf("iidmode(%d)", uint8(m))
	}
}

// AllIIDModes is every declared IIDMode (dhcp-golib#54).
func AllIIDModes() []IIDMode { return []IIDMode{IIDModeEUI64, IIDModeStablePrivacy} }

// MinIIDSecretLen is RFC 7217 §5's "The secret key SHOULD be of at least 128
// bits", in octets, held as a floor (dhcp-golib#54).
const MinIIDSecretLen = 16

// IDGenRetries is RFC 7217 §7's IDGEN_RETRIES: the tentative addresses tried
// after the first one DAD found in use (dhcp-golib#54).
const IDGenRetries = 3

// The errors New6 answers a stable-privacy Params6 it cannot run with (dhcp-golib#54).
var (
	// ErrBadIIDMode is a Params6.IID outside the declared set (dhcp-golib#54).
	ErrBadIIDMode = errors.New("proto: Params6.IID is not a declared identifier mode")
	// ErrShortIIDSecret is a stable-privacy IIDSecret under MinIIDSecretLen octets (dhcp-golib#54).
	ErrShortIIDSecret = errors.New("proto: Params6.IIDSecret is shorter than 16 octets (RFC 7217 section 5)")
	// ErrNoIIDNetIface is a stable-privacy Params6 with an empty IIDNetIface (dhcp-golib#54).
	ErrNoIIDNetIface = errors.New("proto: Params6.IIDNetIface is required for a stable-privacy identifier (RFC 7217 section 5)")
)

// StablePrivacyIID is RFC 7217 §5's F(Prefix, Net_Iface, Network_ID,
// DAD_Counter, secret_key), with SHA-256 as F.
//
// The input is the masked prefix's 16 octets and its length octet, Net_Iface
// and Network_ID each behind its uvarint length, the counter octet, then the
// secret: the lengths keep ("ab","c") and ("a","bc") apart. The identifier is
// the digest's last 8 octets, §5 step 2's "starting from the least significant
// bit"; the u/g bit is left as hashed, §5 treats every bit as opaque
// (dhcp-golib#54).
func StablePrivacyIID(prefix netip.Prefix, netIface, networkID []byte, dadCounter uint8, secret []byte) [8]byte {
	prefix = prefix.Masked()
	a := prefix.Addr().As16()
	in := make([]byte, 0, 17+2*binary.MaxVarintLen64+len(netIface)+len(networkID)+1+len(secret))
	in = append(in, a[:]...)
	in = append(in, byte(prefix.Bits()))
	in = binary.AppendUvarint(in, uint64(len(netIface)))
	in = append(in, netIface...)
	in = binary.AppendUvarint(in, uint64(len(networkID)))
	in = append(in, networkID...)
	in = append(in, dadCounter)
	in = append(in, secret...)
	sum := sha256.Sum256(in)
	var iid [8]byte
	copy(iid[:], sum[len(sum)-8:])
	return iid
}

// iidSource is the part of Params6 an interface identifier is formed from (dhcp-golib#54).
type iidSource struct {
	mode                        IIDMode
	hw                          []byte
	netIface, networkID, secret []byte
}

func (p Params6) iidSource() iidSource {
	return iidSource{mode: p.IID, hw: p.LinkAddr, netIface: p.IIDNetIface, networkID: p.IIDNetworkID, secret: p.IIDSecret}
}

// iid is the identifier this source forms for prefix at counter (dhcp-golib#54).
func (s iidSource) iid(prefix netip.Prefix, counter uint8) ([8]byte, error) {
	switch s.mode {
	case IIDModeEUI64:
		return ModifiedEUI64(s.hw)
	case IIDModeStablePrivacy:
		return StablePrivacyIID(prefix, s.netIface, s.networkID, counter, s.secret), nil
	default:
		return [8]byte{}, fmt.Errorf("%w: %s", ErrBadIIDMode, s.mode)
	}
}

// retries is how many re-formed addresses a duplicate may cost: RFC 7217 §6
// for stable-privacy, none for EUI-64, whose one identifier has no second
// (dhcp-golib#54).
func (s iidSource) retries() uint8 {
	if s.mode == IIDModeStablePrivacy {
		return IDGenRetries
	}
	return 0
}
