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

	"github.com/go-openapi/strfmt"
	cpms_client "github.com/kyma-project/ip-auth/cpms/client"
	cpms_policy "github.com/kyma-project/ip-auth/cpms/client/policy"
	"github.com/kyma-project/ip-auth/cpms/model"
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
	UsePolicyFile        bool   `yaml:"usePolicyFile"`
	UsePolicyService     bool   `yaml:"usePolicyService"`
	PolicyHost           string `yaml:"policyHost"`
	PolicyProjectId      string `yaml:"policyProjectId"`
	PolicyId             string `yaml:"policyId"`
}

const denyBody = "denied by ip-auth"

var (
	httpPort   = flag.String("http", "8000", "HTTP server port")
	configFile = flag.String("config", "", "Decision service configuration file")
	policyFile = flag.String("policy", "policy.json", "Policy configuration file")
)

type ExtAuthzServer struct {
	httpServer *http.Server
	// For test only
	httpPort chan int
	config   IpAuthConfig
	block    []netip.Prefix
	allow    []netip.Prefix
}

func (s *ExtAuthzServer) isAllowed(extIp string) bool {
	if extIp == "" {
		log.Println("IP address is empty")
		return false
	}
	ip, err := netip.ParseAddr(extIp)
	if err != nil {
		log.Printf("Failed to parse IP: %v", err)
		return false
	}
	// allowlist takes precedence over the blocklist
	for _, p := range s.allow {
		if p.Contains(ip) {
			return true
		}
	}
	for _, p := range s.block {
		if p.Contains(ip) {
			return false
		}
	}
	// by default we allow (if not explicitly allowed or blocked)
	return true
}

func (s *ExtAuthzServer) refreshPolicies(interval int) {
	if s.config.UsePolicyFile {
		s.readPolicyFile(*policyFile)
	}
	if s.config.UsePolicyService {
		s.fetchPolicies()
	}
	if interval > 0 {
		log.Printf("Refreshing policies every %v seconds", interval)
		for range time.Tick(time.Duration(interval) * time.Second) {
			if s.config.UsePolicyFile {
				s.readPolicyFile(*policyFile)
			}
			if s.config.UsePolicyService {
				s.fetchPolicies()
			}
		}
	} else {
		log.Printf("Policy refresh is disabled")
	}
}

func (s *ExtAuthzServer) fetchPolicies() {
	log.Printf("Fetching policies from Policy Service")
	cfg := clientcredentials.Config{
		ClientID:     s.config.ClientId,
		ClientSecret: s.config.ClientSecret,
		TokenURL:     s.config.TokenURL,
	}
	httpClient := cfg.Client(context.Background())
	transportCfg := cpms_client.DefaultTransportConfig().WithHost(s.config.PolicyHost)
	policyClient := cpms_client.NewHTTPClientWithConfig(strfmt.Default, transportCfg)
	policyCallParams := cpms_policy.NewGetV2ListsProjectIDPolicyIDParams().
		WithProjectID(s.config.PolicyProjectId).
		WithPolicyID(s.config.PolicyId).
		WithHTTPClient(httpClient)
	okPolicyListResponse, _, err := policyClient.Policy.GetV2ListsProjectIDPolicyID(policyCallParams)
	if err != nil {
		log.Printf("Failed to get policy list: %v", err)
	}
	if okPolicyListResponse == nil {
		log.Println("Failed to get policy list (empty response)")
	}
	policies := okPolicyListResponse.GetPayload()

	s.applyPolicies(policies)
}

func (s *ExtAuthzServer) applyPolicies(policies []*model.PolicyActivePolicy) {
	var allow, block []netip.Prefix
	for _, policy := range policies {
		for _, policyEntry := range policy.Entries {
			p, err := netip.ParsePrefix(policyEntry.Target)
			if err != nil {
				log.Printf("Failed to parse network: %v", err)
			}
			if policyEntry.Policy == "BLOCK" {
				block = append(block, p)
			} else if policyEntry.Policy == "ALLOW" {
				allow = append(allow, p)
			} else {
				log.Printf("Unknown policy %v for target %v", policyEntry.Policy, policyEntry.Target)
			}
		}
	}
	s.allow = allow
	s.block = block
	log.Printf("Number of network ranges: allowed: %v, blocked: %v", len(s.allow), len(s.block))
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
	if s.isAllowed(extIp) {
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

func (s *ExtAuthzServer) readPolicyFile(policyFile string) {
	log.Printf("Reading policies from %s", policyFile)
	var policies []*model.PolicyActivePolicy
	policiesJson, err := os.ReadFile(policyFile)
	if err != nil {
		panic(err)
	}

	err = json.Unmarshal(policiesJson, &policies)
	if err != nil {
		panic(err)
	}

	s.applyPolicies(policies)
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

	config := IpAuthConfig{UsePolicyFile: true, UsePolicyService: false, PolicyUpdateInterval: 600}
	var block []netip.Prefix

	if *configFile != "" {
		readConfigFile(*configFile, &config)
	}

	s := NewExtAuthzServer(config, block)

	go s.refreshPolicies(config.PolicyUpdateInterval)

	go s.run(fmt.Sprintf(":%s", *httpPort))
	defer s.stop()

	// Wait for the process to be shutdown.
	sigs := make(chan os.Signal, 1)
	signal.Notify(sigs, syscall.SIGINT, syscall.SIGTERM)
	<-sigs
}
