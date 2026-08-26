package monitor

import (
	"encoding/json"
	"net/http"
)

// ServeStream is an SSE handler: it sends the latest sample immediately
// (if one exists yet) and then a fresh event on every subsequent tick,
// until the client disconnects.
func (c *Collector) ServeStream(w http.ResponseWriter, r *http.Request) {
	flusher, ok := w.(http.Flusher)
	if !ok {
		http.Error(w, "streaming unsupported", http.StatusInternalServerError)
		return
	}

	w.Header().Set("Content-Type", "text/event-stream")
	w.Header().Set("Cache-Control", "no-cache")
	w.Header().Set("Connection", "keep-alive")
	w.WriteHeader(http.StatusOK)

	writeEvent := func(s Sample) {
		b, err := json.Marshal(s)
		if err != nil {
			return
		}
		w.Write([]byte("data: "))
		w.Write(b)
		w.Write([]byte("\n\n"))
		flusher.Flush()
	}

	if s, ok := c.Latest(); ok {
		writeEvent(s)
	}

	ch := make(chan Sample, 4)
	c.Subscribe(ch)
	defer c.Unsubscribe(ch)

	for {
		select {
		case <-r.Context().Done():
			return
		case s := <-ch:
			writeEvent(s)
		}
	}
}
