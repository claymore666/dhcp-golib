// Copyright (c) 2026 Christian Kamien. MIT License, see LICENSE.

package wire

import (
	"bytes"
	"testing"
)

// TestOptionsV6CloneSharesNothingAndKeepsOrder: the copy has the same options
// in the same order, a nil stays nil, and no byte slice is shared (dhcp-golib#53).
func TestOptionsV6CloneSharesNothingAndKeepsOrder(t *testing.T) {
	if got := OptionsV6(nil).Clone(); got != nil {
		t.Fatalf("a nil list cloned to %v", got)
	}
	o := OptionsV6{{Code: 56, Data: []byte{1, 2}}, {Code: 17, Data: []byte{3}}, {Code: 56, Data: nil}}
	c := o.Clone()
	o[0].Data[0] = 9
	o[1] = OptionV6{Code: 1}
	if len(c) != 3 || c[0].Code != 56 || !bytes.Equal(c[0].Data, []byte{1, 2}) || c[1].Code != 17 || c[2].Code != 56 {
		t.Fatalf("the copy changed or reordered: %v", c)
	}
}
