package main

import (
	"fmt"
	"net/http"
	"testing"
)

func TestExtAuthz(t *testing.T) {
	server := NewExtAuthzServer()
	// Start the test server on random port.
	go server.run("localhost:0")

	// Prepare the HTTP request.
	httpClient := &http.Client{}
	httpReq, err := http.NewRequest(http.MethodGet, fmt.Sprintf("http://localhost:%d/check", <-server.httpPort), nil)
	if err != nil {
		t.Fatalf(err.Error())
	}

	cases := []struct {
		name   string
		header string
		want   int
	}{
		{
			name:   "HTTP-allow",
			header: "allow",
			want:   http.StatusOK,
		},
		{
			name:   "HTTP-deny",
			header: "deny",
			want:   http.StatusForbidden,
		},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			var got int
			httpReq.Header.Set(checkHeader, tc.header)
			resp, err := httpClient.Do(httpReq)
			if err != nil {
				t.Errorf(err.Error())
			} else {
				got = resp.StatusCode
				resp.Body.Close()
			}
			if got != tc.want {
				t.Errorf("want %d but got %d", tc.want, got)
			}
		})
	}
}
