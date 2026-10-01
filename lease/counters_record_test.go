// Copyright (c) 2026 Christian Kamien. MIT License, see LICENSE.

package lease

import (
	"encoding/json"
	"reflect"
	"strings"
	"testing"
)

// The record half of the counters v1.2.0 exposes: every new Stats field has a
// WireCounters twin with its own JSON key, a record written before them reads
// back with them zero, and a record that outlives a manager keeps what each
// manager counted (claymore666/docker-net-dhcp#1027, #1031, #1119, #1028,
// #214).

// newCounterNames are the Stats fields this change added, one per counter of
// the six types the feature lanes kept in ring 1.
var newCounterNames = []string{
	"IPv6OnlyWaited", "IPv6OnlyIgnored", "IPv6OnlyMalformed",
	"RapidCommitsAccepted", "RapidCommitsRefused",
	"ForcerenewsRenewed", "ForcerenewsAlreadyRenewing", "ForcerenewsAckRefused", "ForcerenewsRefused",
	"TemporaryAddressesGranted", "TemporaryAddressesRefused", "TemporaryAddressesAbsent", "TemporaryAddressesConflicted",
	"PrefixesGranted", "PrefixesRefused", "PrefixesAbsent", "PrefixesChanged",
}

// TestEveryNewCounterIsWiredAndNoneIsFolded: the seventeen new counters have a
// Stats field and a WireCounters field of the same name, and none of them
// appears in statsFoldedInstead, which holds the seven counters the record's
// own events produce and nothing a manager mirrors from ring 1.
func TestEveryNewCounterIsWiredAndNoneIsFolded(t *testing.T) {
	st, wt := reflect.TypeOf(Stats{}), reflect.TypeOf(WireCounters{})
	for _, name := range newCounterNames {
		if _, ok := st.FieldByName(name); !ok {
			t.Errorf("Stats has no %s", name)
		}
		if _, ok := wt.FieldByName(name); !ok {
			t.Errorf("WireCounters has no %s: a record that outlived a manager would lose it", name)
		}
		if _, ok := statsFoldedInstead[name]; ok {
			t.Errorf("%s is named in statsFoldedInstead, which excuses a counter the record's own events produce, and no event does", name)
		}
	}
	if len(statsFoldedInstead) != 7 {
		t.Errorf("statsFoldedInstead names %d fields, want the 7 it held before these counters", len(statsFoldedInstead))
	}
}

// TestTheWireCountersJSONKeysAreSnakeCaseAndUnique: every key is the field's
// snake_case name with omitempty, and no two fields share one, so a new tag
// that collided with a neighbour would show here and not as a silently
// dropped number in a record.
func TestTheWireCountersJSONKeysAreSnakeCaseAndUnique(t *testing.T) {
	wt := reflect.TypeOf(WireCounters{})
	seen := map[string]string{}
	for i := 0; i < wt.NumField(); i++ {
		f := wt.Field(i)
		tag := f.Tag.Get("json")
		key, opts, _ := strings.Cut(tag, ",")
		if key == "" || opts != "omitempty" {
			t.Errorf("%s has json tag %q, want a key with omitempty", f.Name, tag)
			continue
		}
		if key != strings.ToLower(key) || strings.ContainsAny(key, "-. ") {
			t.Errorf("%s has json key %q, want snake_case", f.Name, key)
		}
		if other, dup := seen[key]; dup {
			t.Errorf("%s and %s share the json key %q", f.Name, other, key)
		}
		seen[key] = f.Name
	}
	for _, name := range newCounterNames {
		f, _ := wt.FieldByName(name)
		if f.Type.Kind() != reflect.Uint64 {
			t.Errorf("%s is %s, want uint64", name, f.Type)
		}
	}
}

// TestARecordWrittenByV110ReadsBackWithTheNewCountersZero: a record from the
// release before these counters has none of their keys. It decodes without
// error, every new counter reads zero, the counters it did have survive, and
// writing it again adds none of the new keys.
func TestARecordWrittenByV110ReadsBackWithTheNewCountersZero(t *testing.T) {
	const old = `{"acquisitions":2,"renewals":5,"wire":{"steps":9,"sent":4,"received":3,"reconfigures_accepted":1,"slaac_addresses_formed":2}}`
	var got RecordCounters
	if err := json.Unmarshal([]byte(old), &got); err != nil {
		t.Fatalf("a record of the previous release no longer decodes: %v", err)
	}
	if got.Acquisitions != 2 || got.Wire.Steps != 9 || got.Wire.Sent != 4 || got.Wire.ReconfiguresAccepted != 1 {
		t.Fatalf("the counters it had were lost: %+v", got)
	}
	wv := reflect.ValueOf(got.Wire)
	for _, name := range newCounterNames {
		if v := wv.FieldByName(name).Uint(); v != 0 {
			t.Errorf("%s reads %d from a record that never had it", name, v)
		}
	}
	back, err := json.Marshal(got)
	if err != nil {
		t.Fatalf("marshal: %v", err)
	}
	wt := reflect.TypeOf(WireCounters{})
	for _, name := range newCounterNames {
		f, _ := wt.FieldByName(name)
		key, _, _ := strings.Cut(f.Tag.Get("json"), ",")
		if strings.Contains(string(back), `"`+key+`"`) {
			t.Errorf("writing the record again put %q in it: %s", key, back)
		}
	}
}

// TestTheNewCountersSurviveTheJSONForm: a record that carries every new counter
// writes each under its own key and reads each back, with a value unique to
// that field so two swapped fields cannot cancel.
func TestTheNewCountersSurviveTheJSONForm(t *testing.T) {
	var in RecordCounters
	iv := reflect.ValueOf(&in.Wire).Elem()
	for i, name := range newCounterNames {
		iv.FieldByName(name).SetUint(uint64(100 + i))
	}
	line, err := json.Marshal(in)
	if err != nil {
		t.Fatalf("marshal: %v", err)
	}
	var out RecordCounters
	if err := json.Unmarshal(line, &out); err != nil {
		t.Fatalf("unmarshal: %v", err)
	}
	if out.Wire != in.Wire {
		t.Errorf("read back %+v, want %+v", out.Wire, in.Wire)
	}
	if n := strings.Count(string(line), `":1`); n < len(newCounterNames) {
		t.Errorf("the record carries %d of the %d new keys: %s", n, len(newCounterNames), line)
	}
}

// TestEveryNewCounterAccumulatesAcrossManagerInstances is the shape of
// TestStatsAccumulateAcrossManagerInstances for the new fields, each with a
// value unique to it: a snapshot repeated by one manager is cumulative, and a
// second manager's counts add.
func TestEveryNewCounterAccumulatesAcrossManagerInstances(t *testing.T) {
	var first, second, again Stats
	fv, sv, av := reflect.ValueOf(&first).Elem(), reflect.ValueOf(&second).Elem(), reflect.ValueOf(&again).Elem()
	for i, name := range newCounterNames {
		fv.FieldByName(name).SetUint(uint64(10 + i))
		av.FieldByName(name).SetUint(uint64(10 + i + 5))
		sv.FieldByName(name).SetUint(uint64(1000 + i))
	}
	rec := recordAt(t, PhaseJoined)
	apply := func(manager string, s Stats) {
		t.Helper()
		next, err := Fold(rec, RecordEvent{ID: "rec-1", Seq: rec.Seq + 1, Op: OpStats, Instance: "plugin-1", Manager: manager, Stats: &s})
		if err != nil {
			t.Fatalf("merging %s: %v", manager, err)
		}
		rec = next
	}
	apply("mgr-1", first)
	apply("mgr-1", again)
	apply("mgr-2", second)
	wv := reflect.ValueOf(rec.Counters.Wire)
	for i, name := range newCounterNames {
		want := uint64(10+i+5) + uint64(1000+i)
		if got := wv.FieldByName(name).Uint(); got != want {
			t.Errorf("%s = %d after two managers, want %d: the cumulative snapshot of the first plus all of the second", name, got, want)
		}
	}
}
