package main

import (
	"fmt"
	"net/http"
	"net/netip"
	"testing"
)

func TestExtAuthz(t *testing.T) {
	var config GbaasConfig
	prefix, _ := netip.ParsePrefix("2.57.3.0/24")
	block := []netip.Prefix{prefix}
	server := NewExtAuthzServer(config, block)

	go server.run("localhost:0")

	httpClient := &http.Client{}
	httpReq, err := http.NewRequest(http.MethodGet, fmt.Sprintf("http://localhost:%d/check", <-server.httpPort), nil)
	if err != nil {
		t.Fatalf(err.Error())
	}

	cases := []struct {
		name string
		ip   string
		want int
	}{
		{
			name: "HTTP-allow",
			ip:   "10.10.0.0",
			want: http.StatusOK,
		},
		{
			name: "HTTP-deny",
			ip:   "2.57.3.5",
			want: http.StatusForbidden,
		},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			var got int
			httpReq.Header.Set("x-envoy-external-address", tc.ip)
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
