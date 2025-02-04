package slogconsole

import (
	"context"
	"errors"
	"fmt"
	"log/slog"
	"net/http"
	"slices"
	"strings"
	"sync"
	"time"
)

// Handler is an [slog.Handler] that exposes records over a web console.
//
// It implements [slog.Handler] and [http.Handler]. The HTTP handler accepts
// [server-sent events] requests (with Accept: text/event-stream) and streams
// all records as text to the client. It also serves a simple HTML page that
// connects to the SSE endpoint and prints the logs (with Accept: text/html).
//
// The slog Handler will accept all records (Enabled returns true) if there are
// any web clients connected, and none otherwise. If a client is too slow to
// consume records, they will be dropped.
//
// [server-sent events]: https://html.spec.whatwg.org/multipage/server-sent-events.html
type Handler struct {
	ch *commonHandler
	sh slog.Handler
}

// commonHandler is where all the actual state is.
//
// We need to wrap it to support swapping the slog.Handler for WithAttrs and
// WithGroup. This feels like a significant shortcoming of the slog.Handler
// interface, adding a lot of complexity to otherwise simple Handler
// implementations. (Note how [slog.TextHandler] has to do the same thing.)
type commonHandler struct {
	mu      sync.RWMutex
	clients []chan []byte
	limit   int
}

var _ http.Handler = &Handler{}
var _ slog.Handler = &Handler{}

// New returns a new Handler.
//
// opts can be nil, and is passed to [slog.NewTextHandler].
// If Level is not set, it defaults to slog.LevelDebug.
func New(opts *slog.HandlerOptions) *Handler {
	if opts == nil {
		opts = &slog.HandlerOptions{}
	}
	if opts.Level == nil {
		opts.Level = slog.LevelDebug
	}
	h := &commonHandler{limit: 10}
	sh := slog.NewTextHandler(h, opts)
	return &Handler{ch: h, sh: sh}
}

// Handle implements [slog.Handler].
func (h *Handler) Handle(ctx context.Context, r slog.Record) error {
	return h.sh.Handle(ctx, r)
}

// WithAttrs implements [slog.Handler].
func (h *Handler) WithAttrs(attrs []slog.Attr) slog.Handler {
	return &Handler{ch: h.ch, sh: h.sh.WithAttrs(attrs)}
}

// WithGroup implements [slog.Handler].
func (h *Handler) WithGroup(name string) slog.Handler {
	return &Handler{ch: h.ch, sh: h.sh.WithGroup(name)}
}

// Enabled implements [slog.Handler].
func (h *Handler) Enabled(_ context.Context, _ slog.Level) bool {
	h.ch.mu.RLock()
	defer h.ch.mu.RUnlock()
	return len(h.ch.clients) > 0
}

func (h *commonHandler) Write(b []byte) (int, error) {
	h.mu.RLock()
	clients := h.clients
	h.mu.RUnlock()

	for _, c := range clients {
		select {
		case c <- b:
		default:
		}
	}

	return len(b), nil
}

// SetLimit sets the maximum number of clients that can connect to the handler.
// If the limit is reached, new clients will receive a 503 Service Unavailable
// response.
//
// The default limit is 10.
func (h *Handler) SetLimit(limit int) {
	h.ch.mu.Lock()
	defer h.ch.mu.Unlock()
	h.ch.limit = limit
}

// ServeHTTP implements [http.Handler].
func (h *Handler) ServeHTTP(w http.ResponseWriter, r *http.Request) {
	accept := strings.Split(r.Header.Get("Accept"), ",")
	for _, a := range accept {
		a, _, _ := strings.Cut(a, ";")
		switch a {
		case "text/event-stream":
			h.ch.serveSSE(w, r)
			return
		case "text/html":
			h.ch.serveHTML(w, r)
			return
		}
	}
	http.Error(w, "unsupported Accept", http.StatusNotAcceptable)
}

func (h *commonHandler) serveSSE(w http.ResponseWriter, r *http.Request) {
	rc := http.NewResponseController(w)

	w.Header().Set("Content-Type", "text/event-stream")
	w.Header().Set("Cache-Control", "no-cache")
	w.WriteHeader(http.StatusOK)
	rc.Flush()

	ch := make(chan []byte, 10)
	h.mu.Lock()
	if len(h.clients) > h.limit {
		h.mu.Unlock()
		http.Error(w, "too many clients", http.StatusServiceUnavailable)
		return
	}
	h.clients = append(h.clients, ch)
	h.mu.Unlock()
	defer func() {
		h.mu.Lock()
		defer h.mu.Unlock()
		h.clients = slices.DeleteFunc(h.clients, func(c chan []byte) bool { return c == ch })
	}()

	// Override the default strict deadline, but force the client to reconnect
	// occasionally (which is handled by the browser).
	rc.SetWriteDeadline(time.Now().Add(30 * time.Minute))

	for {
		select {
		case b := <-ch:
			// Note that TextHandler promises "a single line" "in a single
			// serialized call to io.Writer.Write" for each Record.
			if _, err := fmt.Fprintf(w, "data: %s\n", b); err != nil {
				return
			}
			rc.Flush()
		case <-r.Context().Done():
			return
		}
	}
}

func (h *commonHandler) serveHTML(w http.ResponseWriter, _ *http.Request) {
	w.Header().Set("Content-Type", "text/html")
	fmt.Fprintf(w, `
		<!DOCTYPE html>
		<title>litewitness</title>
		<meta name="viewport" content="width=device-width, initial-scale=1">
		<style>
			pre {
				font-family: ui-monospace, 'Cascadia Code', 'Source Code Pro',
					Menlo, Consolas, 'DejaVu Sans Mono', monospace;
			}
			:root {
				color-scheme: light dark;
			}
		</style>
		<pre></pre>
		<script>
			const es = new EventSource("");
			const pre = document.querySelector("pre");
			const html = document.querySelector("html");
			function log(txt) {
				const atBottom = html.scrollTop + html.clientHeight >= html.scrollHeight;
				pre.textContent += txt + "\n";
				if (atBottom) html.scrollTop = html.scrollHeight;
			}
			es.onopen = () => log("connected");
			es.onerror = () => log("connection lost");
			es.onmessage = e => log(e.data);
		</script>`)
}

type multiHandler []slog.Handler

// MultiHandler returns a Handler that handles each record with all the given
// handlers.
func MultiHandler(handlers ...slog.Handler) slog.Handler {
	return multiHandler(handlers)
}

func (h multiHandler) Enabled(ctx context.Context, l slog.Level) bool {
	for i := range h {
		if h[i].Enabled(ctx, l) {
			return true
		}
	}
	return false
}

func (h multiHandler) Handle(ctx context.Context, r slog.Record) error {
	var errs []error
	for i := range h {
		if h[i].Enabled(ctx, r.Level) {
			if err := h[i].Handle(ctx, r.Clone()); err != nil {
				errs = append(errs, err)
			}
		}
	}
	return errors.Join(errs...)
}

func (h multiHandler) WithAttrs(attrs []slog.Attr) slog.Handler {
	handlers := make([]slog.Handler, 0, len(h))
	for i := range h {
		handlers = append(handlers, h[i].WithAttrs(attrs))
	}
	return multiHandler(handlers)
}

func (h multiHandler) WithGroup(name string) slog.Handler {
	handlers := make([]slog.Handler, 0, len(h))
	for i := range h {
		handlers = append(handlers, h[i].WithGroup(name))
	}
	return multiHandler(handlers)
}
