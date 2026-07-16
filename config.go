package singproxy

import "time"

const (
	defaultDialTimeout      = 30 * time.Second
	defaultDirectTimeout    = 5 * time.Second
	defaultXHTTPDialTimeout = 30 * time.Second
)

type Config struct {
	DialTimeout      time.Duration
	DirectTimeout    time.Duration
	XHTTPDialTimeout time.Duration
}

func DefaultConfig() Config {
	return Config{
		DialTimeout:      defaultDialTimeout,
		DirectTimeout:    defaultDirectTimeout,
		XHTTPDialTimeout: defaultXHTTPDialTimeout,
	}
}

func (c Config) withDefaults() Config {
	if c.DialTimeout == 0 {
		c.DialTimeout = defaultDialTimeout
	}
	if c.DirectTimeout == 0 {
		c.DirectTimeout = defaultDirectTimeout
	}
	if c.XHTTPDialTimeout == 0 {
		c.XHTTPDialTimeout = defaultXHTTPDialTimeout
	}
	return c
}
