package console

import (
	"bufio"
	"net"
	"net/http"
	"testing"
)

// hijackableRecorder is a minimal http.ResponseWriter that also satisfies
// http.Hijacker, standing in for the real *http.response the server passes to
// handlers.
type hijackableRecorder struct {
	http.ResponseWriter
}

func (hijackableRecorder) Hijack() (net.Conn, *bufio.ReadWriter, error) {
	return nil, nil, nil
}

// unwrapOnlyWriter mimics the session manager's response-writer wrapper: it
// embeds the http.ResponseWriter interface (so it is NOT itself an
// http.Hijacker) and exposes the underlying writer only through Unwrap().
type unwrapOnlyWriter struct {
	http.ResponseWriter
}

func (w unwrapOnlyWriter) Unwrap() http.ResponseWriter { return w.ResponseWriter }

func TestHijackableResponseWriterUnwrapsToHijacker(t *testing.T) {
	hijacker := hijackableRecorder{}
	// Two layers of non-hijacker wrapping, as middleware can stack.
	var wrapped http.ResponseWriter = unwrapOnlyWriter{ResponseWriter: unwrapOnlyWriter{ResponseWriter: hijacker}}

	if _, ok := wrapped.(http.Hijacker); ok {
		t.Fatal("test setup wrong: wrapper must not itself be an http.Hijacker")
	}

	got := hijackableResponseWriter(wrapped)
	if _, ok := got.(http.Hijacker); !ok {
		t.Fatalf("hijackableResponseWriter did not unwrap to an http.Hijacker; got %T", got)
	}
}

func TestHijackableResponseWriterReturnsHijackerAsIs(t *testing.T) {
	hijacker := hijackableRecorder{}
	if got := hijackableResponseWriter(hijacker); got != http.ResponseWriter(hijacker) {
		t.Fatalf("expected the hijacker to be returned unchanged, got %T", got)
	}
}

// nonHijackWriter is neither an http.Hijacker nor unwrappable; the helper must
// return it unchanged rather than loop forever.
type nonHijackWriter struct {
	http.ResponseWriter
}

func TestHijackableResponseWriterReturnsNonUnwrappableAsIs(t *testing.T) {
	w := nonHijackWriter{}
	if got := hijackableResponseWriter(w); got != http.ResponseWriter(w) {
		t.Fatalf("expected the non-unwrappable writer to be returned unchanged, got %T", got)
	}
}
