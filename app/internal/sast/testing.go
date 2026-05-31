package sast

import "testing"

// SetAPIForTest redirects the package-level Anthropic endpoint to the given
// URL for the duration of the test. It restores the original value on test
// cleanup. Tests using this helper must not run in parallel with other tests
// that also mutate the endpoint.
func SetAPIForTest(t *testing.T, url string) {
	t.Helper()
	prev := anthropicAPI
	anthropicAPI = url
	t.Cleanup(func() { anthropicAPI = prev })
}
