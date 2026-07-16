package singproxy

import (
	"errors"
	"net"
)

var (
	ErrInvalidProxyFormat      = errors.New("invalid proxy format")
	ErrUnsupportedScheme       = errors.New("unsupported proxy scheme")
	ErrMissingTarget           = errors.New("missing target")
	ErrProxyDialTimeoutReached = &net.OpError{
		Op:  "dial",
		Net: "proxy dial timeout",
		Err: errors.New("proxy dial timed out"),
	}
)
