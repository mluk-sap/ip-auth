package main

import (
	"context"
	"encoding/json"
	"flag"
	"fmt"
	"io"
	"log"
	"net"
	"net/http"
	"net/netip"
	"os"
	"os/signal"
	"sync"
	"syscall"
	"time"

	"golang.org/x/oauth2/clientcredentials"
	"gopkg.in/yaml.v3"
)

type IpAuthConfig struct {
	ClientId             string `yaml:"clientId"`
	ClientSecret         string `yaml:"clientSecret"`
	TokenURL             string `yaml:"tokenUrl"`
	PolicyURL            string `yaml:"policyUrl"`
	PolicyUpdateInterval int    `yaml:"policyUpdateInterval"`
	Payload              string `yaml:"payload"`
}

const denyBody = "denied by ip-auth"

var (
	httpPort   = flag.String("http", "8000", "HTTP server port")
	configFile = flag.String("config", "", "Decision service configuration file")
	policyFile = flag.String("policy", "", "Policy configuration file")
)

type ExtAuthzServer struct {
	httpServer *http.Server
	// For test only
	httpPort chan int
	config   IpAuthConfig
	block    []netip.Prefix
}

func (s *ExtAuthzServer) isBlocked(extIp string) bool {
	ip, err := netip.ParseAddr(extIp)
	if err != nil {
		log.Fatalf("Failed to parse IP: %v", err)
	}
	for _, p := range s.block {
		if p.Contains(ip) {
			return false
		}
	}
	return true
}

func (s *ExtAuthzServer) refreshPolicies(interval int) {
	if interval > 0 {
		log.Printf("Refreshing policies every %v seconds", interval)
		for range time.Tick(time.Duration(interval) * time.Second) {
			s.fetchPolicies()
		}
	} else {
		log.Printf("Policy refresh is disabled")
	}

}

func (s *ExtAuthzServer) fetchPolicies() {
	log.Printf("Fetching policies")
	cfg := clientcredentials.Config{
		ClientID:     s.config.ClientId,
		ClientSecret: s.config.ClientSecret,
		TokenURL:     s.config.TokenURL,
	}
	client := cfg.Client(context.Background())
	res, err := client.Get(s.config.PolicyURL)
	if err != nil {
		log.Fatalf("Failed to get policies: %v", err)
	}
	resBody, err := io.ReadAll(res.Body)
	defer res.Body.Close()
	if err != nil {
		log.Fatalf("Failed to read response body: %v", err)
	}
	policies := []map[string]string{}
	err = json.Unmarshal(resBody, &policies)
	if err != nil {
		log.Fatalf("Failed to parse policies: %v", err)
	}
	var block []netip.Prefix

	for _, policy := range policies {
		if policy["policy"] == "BLOCK_ACCESS" {
			p, err := netip.ParsePrefix(policy["network"])
			if err != nil {
				log.Fatalf("Failed to parse network: %v", err)
			}
			block = append(block, p)
		}
	}
	s.block = block
	log.Printf("Number of blocked network ranges: %v", len(s.block))

}

// ServeHTTP implements the HTTP check request.
func (s *ExtAuthzServer) ServeHTTP(response http.ResponseWriter, request *http.Request) {
	_, err := io.ReadAll(request.Body)
	if err != nil {
		log.Printf("[HTTP] read body failed: %v", err)
	}
	extIp := request.Header.Get("x-envoy-external-address")
	l := fmt.Sprintf("%s %s%s, ip: %v\n", request.Method, request.Host, request.URL, extIp)
	log.Printf("External IP: %s", extIp)
	if s.isBlocked(extIp) {
		log.Printf("[HTTP][allowed]: %s", l)
		response.WriteHeader(http.StatusOK)
	} else {
		log.Printf("[HTTP][denied]: %s", l)
		response.WriteHeader(http.StatusForbidden)
		_, _ = response.Write([]byte(denyBody))
	}
}

func (s *ExtAuthzServer) startHTTP(address string, wg *sync.WaitGroup) {
	defer func() {
		wg.Done()
		log.Printf("Stopped HTTP server")
	}()

	listener, err := net.Listen("tcp", address)
	if err != nil {
		log.Fatalf("Failed to create HTTP server: %v", err)
	}
	// Store the port for test only.
	s.httpPort <- listener.Addr().(*net.TCPAddr).Port
	s.httpServer = &http.Server{Handler: s}

	log.Printf("Starting HTTP server at %s", listener.Addr())
	if err := s.httpServer.Serve(listener); err != nil {
		log.Fatalf("Failed to start HTTP server: %v", err)
	}
}

func (s *ExtAuthzServer) run(httpAddr string) {
	var wg sync.WaitGroup
	wg.Add(2)
	go s.startHTTP(httpAddr, &wg)
	wg.Wait()
}

func (s *ExtAuthzServer) stop() {
	log.Printf("HTTP server stopped: %v", s.httpServer.Close())
}

func NewExtAuthzServer(config IpAuthConfig, block []netip.Prefix) *ExtAuthzServer {
	return &ExtAuthzServer{
		httpPort: make(chan int, 1),
		config:   config,
		block:    block,
	}
}

func readPolicyFile(policyFile string) []netip.Prefix {
	policies := []map[string]string{}
	policiesJson, err := os.ReadFile(policyFile)
	if err != nil {
		panic(err)
	}

	err = json.Unmarshal(policiesJson, &policies)
	if err != nil {
		panic(err)
	}
	var block []netip.Prefix

	for _, policy := range policies {
		if policy["policy"] == "BLOCK_ACCESS" {
			p, err := netip.ParsePrefix(policy["network"])
			if err != nil {
				log.Fatalf("Failed to parse network: %v", err)
			}
			block = append(block, p)
		}
	}
	return block
}

func readConfigFile(configFile string, config *IpAuthConfig) {
	source, err := os.ReadFile(configFile)
	if err != nil {
		panic(err)
	}

	err = yaml.Unmarshal(source, config)
	if err != nil {
		panic(err)
	}
}

func main() {
	flag.Parse()

	var config IpAuthConfig
	var block []netip.Prefix

	if *policyFile != "" {
		block = readPolicyFile(*policyFile)
		log.Printf("%v policies loaded from %v\n", len(block), *policyFile)
	}
	if *configFile != "" {
		readConfigFile(*configFile, &config)
	}

	s := NewExtAuthzServer(config, block)
	s.fetchPolicies()

	go s.refreshPolicies(config.PolicyUpdateInterval)

	go s.run(fmt.Sprintf(":%s", *httpPort))
	defer s.stop()

	// Wait for the process to be shutdown.
	sigs := make(chan os.Signal, 1)
	signal.Notify(sigs, syscall.SIGINT, syscall.SIGTERM)
	<-sigs
}
