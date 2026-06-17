package sshtunnel

import (
	"context"
	"fmt"
	"time"
)

// keepAliveRequest is an out-of-band SSH global request sent purely to prove the
// transport is still alive. The relay replies with a failure because the
// request name is unknown to it, but any reply still confirms the connection.
const keepAliveRequest = "keepalive@devbox-gateway"

// keepAliveSender is the subset of *ssh.Client used to probe liveness; it keeps
// the keepalive logic testable without a live SSH connection.
type keepAliveSender interface {
	SendRequest(name string, wantReply bool, payload []byte) (bool, []byte, error)
}

// keepAlive probes the tunnel on each tick. The first failed probe is reported
// on the fatal channel and tears the tunnel down so the accept loop unblocks.
func (t *Tunnel) keepAlive(ctx context.Context, interval, timeout time.Duration) {
	ticker := time.NewTicker(interval)
	defer ticker.Stop()

	for {
		select {
		case <-ctx.Done():
			return
		case <-ticker.C:
		}

		if err := sendKeepAlive(t.client, timeout); err != nil {
			// Buffered (cap 1) and only ever sent once, so this never blocks.
			t.fatal <- err
			_ = t.Close()
			return
		}
	}
}

func sendKeepAlive(sender keepAliveSender, timeout time.Duration) error {
	result := make(chan error, 1)
	go func() {
		// A request-failure reply still proves the SSH transport is alive.
		_, _, err := sender.SendRequest(keepAliveRequest, true, nil)
		result <- err
	}()

	timer := time.NewTimer(timeout)
	defer timer.Stop()

	select {
	case err := <-result:
		if err != nil {
			return fmt.Errorf("SSH keepalive failed: %w", err)
		}
		return nil
	case <-timer.C:
		// Closing the SSH client (done by the caller on shutdown) unblocks the
		// pending SendRequest goroutine above.
		return fmt.Errorf("SSH keepalive timed out after %s", timeout)
	}
}
