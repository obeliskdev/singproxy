package singproxy

import (
	"errors"
	"io"
	"net"
	"sync"
	"time"
)

type xhttpConn struct {
	writer  io.WriteCloser
	reader  io.ReadCloser
	onClose func()

	remoteAddr net.Addr
	localAddr  net.Addr

	deadline *time.Timer
}

func (c *xhttpConn) Write(b []byte) (int, error) { return c.writer.Write(b) }
func (c *xhttpConn) Read(b []byte) (int, error)  { return c.reader.Read(b) }

func (c *xhttpConn) Close() error {
	err := c.writer.Close()
	err2 := c.reader.Close()
	if c.onClose != nil {
		c.onClose()
	}
	return errors.Join(err, err2)
}

func (c *xhttpConn) LocalAddr() net.Addr  { return c.localAddr }
func (c *xhttpConn) RemoteAddr() net.Addr { return c.remoteAddr }

func (c *xhttpConn) SetDeadline(t time.Time) error      { return c.setDeadline(t) }
func (c *xhttpConn) SetReadDeadline(t time.Time) error  { return c.setDeadline(t) }
func (c *xhttpConn) SetWriteDeadline(t time.Time) error { return c.setDeadline(t) }

func (c *xhttpConn) setDeadline(t time.Time) error {
	if t.IsZero() {
		if c.deadline != nil {
			c.deadline.Stop()
			c.deadline = nil
		}
		return nil
	}
	d := time.Until(t)
	if c.deadline != nil {
		c.deadline.Reset(d)
		return nil
	}
	c.deadline = time.AfterFunc(d, func() { _ = c.Close() })
	return nil
}

var _ net.Conn = (*xhttpConn)(nil)

type xhttpWaitReadCloser struct {
	wait chan struct{}
	once sync.Once
	rc   io.ReadCloser
	err  error
}

func newXhttpWaitReadCloser() *xhttpWaitReadCloser {
	return &xhttpWaitReadCloser{wait: make(chan struct{})}
}

func (w *xhttpWaitReadCloser) Set(rc io.ReadCloser) {
	w.setup(rc, nil)
}

func (w *xhttpWaitReadCloser) CloseWithError(err error) {
	w.setup(nil, err)
}

func (w *xhttpWaitReadCloser) setup(rc io.ReadCloser, err error) {
	w.once.Do(func() {
		w.rc = rc
		w.err = err
		close(w.wait)
	})
	if w.err != nil && rc != nil {
		_ = rc.Close()
	}
}

func (w *xhttpWaitReadCloser) Read(b []byte) (int, error) {
	<-w.wait
	if w.rc == nil {
		return 0, w.err
	}
	return w.rc.Read(b)
}

func (w *xhttpWaitReadCloser) Err() error {
	<-w.wait
	return w.err
}

func (w *xhttpWaitReadCloser) Close() error {
	w.setup(nil, net.ErrClosed)
	<-w.wait
	if w.rc != nil {
		return w.rc.Close()
	}
	return nil
}
