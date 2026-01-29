package proxy

import (
	"bufio"
	"bytes"
	"io"
	"net/http"
	"strings"
)

// ForwardSSE forwards a Server-Sent Events stream to the client.
func ForwardSSE(w http.ResponseWriter, body io.ReadCloser) (accumulated string, err error) {
	flusher, ok := w.(http.Flusher)
	if !ok {
		data, _ := io.ReadAll(body)
		w.Write(data)
		return string(data), nil
	}

	w.Header().Set("Content-Type", "text/event-stream")
	w.Header().Set("Cache-Control", "no-cache")
	w.Header().Set("Connection", "keep-alive")

	var buf bytes.Buffer
	scanner := bufio.NewScanner(io.TeeReader(body, &buf))
	for scanner.Scan() {
		line := scanner.Text()
		w.Write([]byte(line + "\n"))
		if line == "" || strings.HasPrefix(line, "data:") {
			flusher.Flush()
		}
	}
	return buf.String(), scanner.Err()
}

// ForwardNDJSON forwards a newline-delimited JSON stream to the client (used by Ollama).
func ForwardNDJSON(w http.ResponseWriter, body io.ReadCloser) (accumulated string, err error) {
	flusher, ok := w.(http.Flusher)
	if !ok {
		data, _ := io.ReadAll(body)
		w.Write(data)
		return string(data), nil
	}

	w.Header().Set("Content-Type", "application/x-ndjson")
	w.Header().Set("Cache-Control", "no-cache")
	w.Header().Set("Connection", "keep-alive")

	var buf bytes.Buffer
	scanner := bufio.NewScanner(io.TeeReader(body, &buf))
	for scanner.Scan() {
		line := scanner.Text()
		w.Write([]byte(line + "\n"))
		flusher.Flush()
	}
	return buf.String(), scanner.Err()
}
