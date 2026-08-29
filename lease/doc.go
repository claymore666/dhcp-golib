// Package lease is ring 2: the manager. One managed lease per
// (interface, family). It turns the actions ring 1 returns into requests on
// ring 3 and reports lease changes outward.
//
// Empty at M0 by design.
package lease
