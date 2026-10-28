package output

import (
	"fmt"
	"github.com/projectdiscovery/goflags"
	"strings"
	"testing"

	"github.com/pkg/errors"
	"github.com/projectdiscovery/nuclei/v3/pkg/types"
	"github.com/stretchr/testify/require"
)

func TestStandardWriterRequest(t *testing.T) {
	t.Run("WithoutTraceAndError", func(t *testing.T) {
		w, err := NewStandardWriter(&types.Options{})
		require.NoError(t, err)
		require.NotPanics(t, func() {
			w.Request("path", "input", "http", nil)
			w.Close()
		})
	})

	t.Run("TraceAndErrorWithoutError", func(t *testing.T) {
		traceWriter := &testWriteCloser{}
		errorWriter := &testWriteCloser{}

		w, err := NewStandardWriter(&types.Options{})
		w.traceFile = traceWriter
		w.errorFile = errorWriter
		require.NoError(t, err)
		w.Request("path", "input", "http", nil)

		require.Equal(t, `{"template":"path","type":"http","input":"input","address":"input:","error":"none"}`, traceWriter.String())
		require.Empty(t, errorWriter.String())
	})

	t.Run("ErrorWithWrappedError", func(t *testing.T) {
		errorWriter := &testWriteCloser{}

		w, err := NewStandardWriter(&types.Options{})
		w.errorFile = errorWriter
		require.NoError(t, err)
		w.Request(
			"misconfiguration/tcpconfig.yaml",
			"https://example.com/tcpconfig.html",
			"http",
			fmt.Errorf("GET https://example.com/tcpconfig.html/tcpconfig.html giving up after 2 attempts: %w", errors.New("context deadline exceeded (Client.Timeout exceeded while awaiting headers)")),
		)

		require.Equal(t, `{"template":"misconfiguration/tcpconfig.yaml","type":"http","input":"https://example.com/tcpconfig.html","address":"example.com:443","error":"cause=\"context deadline exceeded (Client.Timeout exceeded while awaiting headers)\"","kind":"unknown-error"}`, errorWriter.String())
	})
}

// Credential headers are masked by default; -no-redact keeps them while keys
// given with -redact are still masked.
func TestStandardWriterNoRedact(t *testing.T) {
	const request = "GET / HTTP/1.1\r\nCookie: session=abc\r\nX-Token: secret\r\n\r\n"
	const response = "HTTP/1.1 200 OK\r\nSet-Cookie: session=abc\r\n\r\n"

	cases := []struct {
		name     string
		options  *types.Options
		request  string
		response string
	}{
		{"default", &types.Options{}, "GET / HTTP/1.1\r\nCookie: ***\r\nX-Token: secret\r\n\r\n", "HTTP/1.1 200 OK\r\nSet-Cookie: ***\r\n\r\n"},
		{"no-redact", &types.Options{NoRedact: true}, request, response},
		{"no-redact with keys", &types.Options{NoRedact: true, Redact: goflags.StringSlice{"X-Token"}}, "GET / HTTP/1.1\r\nCookie: session=abc\r\nX-Token: ***\r\n\r\n", response},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			w, err := NewStandardWriter(tc.options)
			require.NoError(t, err)
			w.DisableStdout = true

			event := &ResultEvent{Request: request, Response: response, CURLCommand: "curl -H 'Cookie: session=abc' https://example.com"}
			require.NoError(t, w.Write(event))

			require.Equal(t, tc.request, event.Request)
			require.Equal(t, tc.response, event.Response)
			if tc.options.NoRedact {
				require.Equal(t, "curl -H 'Cookie: session=abc' https://example.com", event.CURLCommand)
			} else {
				require.Equal(t, "curl -H 'Cookie: ***' https://example.com", event.CURLCommand)
			}
		})
	}
}

type testWriteCloser struct {
	strings.Builder
}

func (w testWriteCloser) Close() error {
	return nil
}
