package singproxy

import (
	"errors"
	"net"
)

var (
	ErrInvalidProxyFormat = errors.New("invalid proxy format")
	ErrUnsupportedScheme  = errors.New("unsupported proxy scheme")
	ErrMissingTarget      = errors.New("missing target")
	ErrProxyClosed        = errors.New("proxy is closed")
)

// ErrProxyDialTimeoutReached returns a fresh error value describing a
// proxy dial that exceeded its configured timeout. A factory is used
// instead of a shared sentinel because *net.OpError values may carry
// per-call source information and must never be shared across calls.
func ErrProxyDialTimeoutReached() error {
	return &net.OpError{
		Op:  "dial",
		Net: "proxy dial timeout",
		Err: errors.New("proxy dial timed out"),
	}
}
