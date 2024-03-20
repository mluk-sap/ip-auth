package main

import (
	"bytes"
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
	"strings"
	"sync"
	"syscall"

	"golang.org/x/oauth2/clientcredentials"
	"gopkg.in/yaml.v3"
)

type GbaasConfig struct {
	ClientId     string `yaml:"clientId"`
	ClientSecret string `yaml:"clientSecret"`
	TokenURL     string `yaml:"tokenUrl"`
	DecisionURL  string `yaml:"decisionUrl"`
	Payload      string `yaml:"payload"`
}

const (
	resultHeader   = "x-ext-authz-check-result"
	receivedHeader = "x-ext-authz-check-received"
	overrideHeader = "x-ext-authz-additional-header-override"
	resultAllowed  = "allowed"
	resultDenied   = "denied"
)

var (
	httpPort   = flag.String("http", "8000", "HTTP server port")
	configFile = flag.String("config", "", "Decision service configuration file")
	policyFile = flag.String("policy", "", "Policy configuration file")

	denyBody = "denied by ip-auth"
)

// ExtAuthzServer implements the ext_authz v2/v3 gRPC and HTTP check request API.
type ExtAuthzServer struct {
	httpServer *http.Server
	// For test only
	httpPort chan int
	config   GbaasConfig
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

func getDecision(config GbaasConfig, extIp string) bool {

	cfg := clientcredentials.Config{
		ClientID:     config.ClientId,
		ClientSecret: config.ClientSecret,
		TokenURL:     config.TokenURL,
	}
	client := cfg.Client(context.Background())

	body := []byte(strings.Replace(config.Payload, "IP_ADDRESS", extIp, 1))
	response, err := client.Post(config.DecisionURL, "application/json", bytes.NewBuffer(body))
	if err != nil {
		log.Fatalf("Failed to get token: %v", err)
	}
	var result map[string]any
	resBody, err := io.ReadAll(response.Body)
	defer response.Body.Close()
	if err != nil {
		log.Fatalf("Failed to read response body: %v", err)
	}
	json.Unmarshal(resBody, &result)

	fmt.Printf("Response: %+v\n", string(resBody))
	fmt.Printf("Result: %+v\n", result)
	return (result["access_allowed"] == true)
}

// ServeHTTP implements the HTTP check request.
func (s *ExtAuthzServer) ServeHTTP(response http.ResponseWriter, request *http.Request) {
	body, err := io.ReadAll(request.Body)
	if err != nil {
		log.Printf("[HTTP] read body failed: %v", err)
	}
	l := fmt.Sprintf("%s %s%s, headers: %v, body: [%s]\n", request.Method, request.Host, request.URL, request.Header, returnIfNotTooLong(string(body)))
	extIp := request.Header.Get("x-envoy-external-address")
	log.Printf("External IP: %s", extIp)
	if s.isBlocked(extIp) {
		log.Printf("[HTTP][allowed]: %s", l)
		response.Header().Set(resultHeader, resultAllowed)
		response.Header().Set(overrideHeader, request.Header.Get(overrideHeader))
		response.Header().Set(receivedHeader, l)
		response.WriteHeader(http.StatusOK)
	} else {
		log.Printf("[HTTP][denied]: %s", l)
		response.Header().Set(resultHeader, resultDenied)
		response.Header().Set(overrideHeader, request.Header.Get(overrideHeader))
		response.Header().Set(receivedHeader, l)
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

func NewExtAuthzServer(config GbaasConfig, block []netip.Prefix) *ExtAuthzServer {
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

func main() {
	flag.Parse()

	var config GbaasConfig
	var block []netip.Prefix

	if *policyFile != "" {
		block = readPolicyFile(*policyFile)
	}
	log.Printf("Number of blocked network ranges: %v", len(block))
	if *configFile != "" {
		fmt.Printf("%+v\n", *configFile)
		source, err := os.ReadFile(*configFile)
		if err != nil {
			panic(err)
		}
		err = yaml.Unmarshal(source, &config)
		if err != nil {
			panic(err)
		}
		fmt.Printf("Config: %+v\n", config)
	}

	s := NewExtAuthzServer(config, block)

	go s.run(fmt.Sprintf(":%s", *httpPort))
	defer s.stop()

	// Wait for the process to be shutdown.
	sigs := make(chan os.Signal, 1)
	signal.Notify(sigs, syscall.SIGINT, syscall.SIGTERM)
	<-sigs
}

func returnIfNotTooLong(body string) string {
	// Maximum size of a header accepted by Envoy is 60KiB, so when the request body is bigger than 60KB,
	// we don't return it in a response header to avoid rejecting it by Envoy and returning 431 to the client
	if len(body) > 60000 {
		return "<too-long>"
	}
	return body
}
