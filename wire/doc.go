// Package wire is ring 0: the codec. Bytes to typed messages and back.
//
// Ring 0 is pure. It holds no clock, opens no socket and touches no ambient
// state; it is subject to the same import policy as ring 1 (see the T1 gate,
// internal/gates/t1), because ring 1 imports it and an impure ring 0 would
// make ring 1 impure transitively.
//
// Empty at M0 by design: the gates are built and proven against an empty
// package, before there is protocol code to bend them around.
package wire
