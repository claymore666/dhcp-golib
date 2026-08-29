package runtime

import (
	"context"
	"fmt"
	"net"

	"github.com/claymore666/dhcplease/lease"
	"github.com/claymore666/dhcplease/proto"
)

// Client is the assembled thing: ring 3's implementations wired into ring 2's
// manager. It is the only type in this library a caller needs in the ordinary
// case.
//
// It is a thin assembly on purpose. Everything it does is choosing which
// implementation goes into which port, and every one of those choices is
// visible and replaceable — the same manager runs against fakes with no root
// and no network, which is what makes the acquisition path table-testable.
type Client struct {
	mgr       *lease.Manager
	transport *PacketTransport
	timers    *Timers
	journal   *Journal
	packets   *PacketRing
}

// ClientConfig configures a Client.
type ClientConfig struct {
	// Interface is the link to lease on.
	Interface string

	// Params is the protocol parameter set. If CHAddr is empty it is filled
	// from the interface's hardware address.
	Params proto.Params

	// JournalSize and PacketRingSize default to DefaultJournalSize and
	// DefaultPacketRingSize. Both are bounded (R3); see those types for what a
	// wrap costs.
	JournalSize    int
	PacketRingSize int

	// EventBuffer is the depth of the outward event channel.
	EventBuffer int
}

// NewClient assembles a Client on the named interface.
//
// The order below matters for cleanup: each resource opened is released if a
// later one fails, because a half-constructed Client has no Close to call.
func NewClient(cfg ClientConfig) (*Client, error) {
	if cfg.Interface == "" {
		return nil, fmt.Errorf("runtime: no interface named")
	}
	if len(cfg.Params.CHAddr) == 0 {
		iface, err := net.InterfaceByName(cfg.Interface)
		if err != nil {
			return nil, fmt.Errorf("runtime: interface %q: %w", cfg.Interface, err)
		}
		cfg.Params.CHAddr = append([]byte(nil), iface.HardwareAddr...)
	}

	ent, err := NewEntropy()
	if err != nil {
		return nil, fmt.Errorf("runtime: entropy: %w", err)
	}

	tr, err := NewPacketTransport(cfg.Interface)
	if err != nil {
		return nil, err
	}

	jsize := cfg.JournalSize
	if jsize == 0 {
		jsize = DefaultJournalSize
	}
	psize := cfg.PacketRingSize
	if psize == 0 {
		psize = DefaultPacketRingSize
	}

	timers := NewTimers()
	c := &Client{
		transport: tr,
		timers:    timers,
		journal:   NewJournal(jsize),
		packets:   NewPacketRing(psize),
	}

	mgr, err := lease.NewManager(lease.Config{
		Params:      cfg.Params,
		Transport:   tr,
		Clock:       Clock{},
		Timers:      timers,
		Entropy:     ent,
		Journal:     c.journal,
		Packets:     c.packets,
		EventBuffer: cfg.EventBuffer,
	})
	if err != nil {
		_ = tr.Close()
		_ = timers.Close()
		return nil, err
	}
	c.mgr = mgr
	return c, nil
}

// Run drives the client until ctx is cancelled. It closes the transport and
// the timers on the way out.
func (c *Client) Run(ctx context.Context) error {
	defer func() {
		_ = c.transport.Close()
		_ = c.timers.Close()
	}()
	return c.mgr.Run(ctx)
}

// Events is the outward lease event stream.
func (c *Client) Events() <-chan lease.Event { return c.mgr.Events() }

// Lease returns a snapshot of the held lease.
func (c *Client) Lease() (lease.Lease, bool) { return c.mgr.Lease() }

// Stats returns the manager's counters.
func (c *Client) Stats() lease.Stats { return c.mgr.Stats() }

// TransportStats returns the socket's counters. Separate from Stats because
// they answer different questions: the manager counts what it processed, the
// transport counts what arrived and was rejected before it. A client that is
// seeing nothing is diagnosed by the difference between them.
func (c *Client) TransportStats() TransportStats { return c.transport.Stats() }

// Journal returns the recorded steps (G2, G6).
func (c *Client) Journal() []proto.JournalEntry { return c.journal.Entries() }

// JournalDropped reports whether the journal ring has wrapped. Non-zero means
// the journal is no longer replayable — see Journal.
func (c *Client) JournalDropped() int { return c.journal.Dropped() }

// Packets returns the captured packets (G1).
func (c *Client) Packets() []lease.CapturedPacket { return c.packets.Packets() }
