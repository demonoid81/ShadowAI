package proxy

import (
	"bufio"
	"bytes"
	"io"
	"net/http"
	"strings"
)

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
