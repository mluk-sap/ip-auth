package main

import (
	"fmt"
	"net/http"
	"net/netip"
	"testing"
)

func TestExtAuthz(t *testing.T) {
	var config IpAuthConfig
	blockedIP, _ := netip.ParsePrefix("2.57.3.0/24")
	blocklist := []netip.Prefix{blockedIP}
	allowedIP, _ := netip.ParsePrefix("2.57.3.1/32")
	allowlist := []netip.Prefix{allowedIP}
	server := NewExtAuthzServer(config, allowlist, blocklist)

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
			name: "HTTP-allow-unknown",
			ip:   "10.10.0.0",
			want: http.StatusOK,
		},
		{
			name: "HTTP-deny-blocklisted",
			ip:   "2.57.3.5",
			want: http.StatusForbidden,
		},
		{
			name: "HTTP-deny-empty",
			ip:   "",
			want: http.StatusForbidden,
		},
		{
			name: "HTTP-allow-allowlisted",
			ip:   "2.57.3.1",
			want: http.StatusOK,
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
