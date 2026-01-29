package proxy

import (
	"net/http"
)

type OpenAITransport struct {
	APIKey   string
	Upstream http.RoundTripper
}

func (t *OpenAITransport) RoundTrip(req *http.Request) (*http.Response, error) {
	req.Header.Set("Authorization", "Bearer "+t.APIKey)
	req.Host = "api.openai.com"
	if t.Upstream != nil {
		return t.Upstream.RoundTrip(req)
	}
	return http.DefaultTransport.RoundTrip(req)
}
