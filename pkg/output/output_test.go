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
	const request = "GET /?tracking=1&x=2 HTTP/1.1\r\nCookie: tracking=1; session=abc\r\nX-Token: secret\r\n\r\n"
	const response = "HTTP/1.1 200 OK\r\nSet-Cookie: session=abc; Path=/\r\n\r\n"
	const curl = "curl -H 'Cookie: tracking=1; session=abc' https://example.com/?tracking=1&x=2"
	const matched = "https://example.com/?tracking=1&x=2"

	cases := []struct {
		name     string
		options  *types.Options
		request  string
		response string
		curl     string
		matched  string
	}{
		{
			"default", &types.Options{},
			"GET /?tracking=1&x=2 HTTP/1.1\r\nCookie: ***\r\nX-Token: secret\r\n\r\n",
			"HTTP/1.1 200 OK\r\nSet-Cookie: ***\r\n\r\n",
			"curl -H 'Cookie: ***' https://example.com/?tracking=1&x=2",
			matched,
		},
		{"no-redact", &types.Options{NoRedact: true}, request, response, curl, matched},
		{
			"no-redact with header key", &types.Options{NoRedact: true, Redact: goflags.StringSlice{"X-Token"}},
			"GET /?tracking=1&x=2 HTTP/1.1\r\nCookie: tracking=1; session=abc\r\nX-Token: ***\r\n\r\n",
			response, curl, matched,
		},
		// One cookie or query parameter is masked; its neighbours stay.
		{
			"no-redact with cookie key", &types.Options{NoRedact: true, Redact: goflags.StringSlice{"tracking"}},
			"GET /?tracking=***&x=2 HTTP/1.1\r\nCookie: tracking=***; session=abc\r\nX-Token: secret\r\n\r\n",
			response,
			"curl -H 'Cookie: tracking=***; session=abc' https://example.com/?tracking=***&x=2",
			"https://example.com/?tracking=***&x=2",
		},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			w, err := NewStandardWriter(tc.options)
			require.NoError(t, err)
			w.DisableStdout = true

			event := &ResultEvent{Request: request, Response: response, CURLCommand: curl, Matched: matched}
			require.NoError(t, w.Write(event))

			require.Equal(t, tc.request, event.Request)
			require.Equal(t, tc.response, event.Response)
			require.Equal(t, tc.curl, event.CURLCommand)
			require.Equal(t, tc.matched, event.Matched)
		})
	}
}

// A `;` inside a query value is part of the value; in a cookie header it is a delimiter.
func TestRedactKeepsSemicolonInsideValue(t *testing.T) {
	patterns := compileRedactPatterns([]string{"password"})
	cases := map[string]string{
		"GET /?password=;s3cr3t&x=2 HTTP/1.1":          "GET /?password=***&x=2 HTTP/1.1",
		"GET /?password=a;b HTTP/1.1":                  "GET /?password=*** HTTP/1.1",
		"https://example.com/?password=a;b":            "https://example.com/?password=***",
		"Cookie: password=x; session=abc\r\n":          "Cookie: password=***; session=abc\r\n",
		"Set-Cookie: password=x; Path=/; HttpOnly\r\n": "Set-Cookie: password=***; Path=/; HttpOnly\r\n",
		"Set-Cookie: password=x; HttpOnly\r\n":         "Set-Cookie: password=***; HttpOnly\r\n",
		"password=a;b&user=u":                          "password=***&user=u",
	}
	for in, want := range cases {
		require.Equal(t, want, redactWithPatterns(in, patterns), in)
	}
}

type testWriteCloser struct {
	strings.Builder
}

func (w testWriteCloser) Close() error {
	return nil
}
