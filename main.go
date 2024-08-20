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
	UsePolicyFile        bool   `yaml:"usePolicyFile"`
	UsePolicyUrl         bool   `yaml:"usePolicyUrl"`
}

type Policy struct {
	Id            string
	ProjectID     string
	VersionID     string
	PolicyVersion string
	Type          string
	Entries       []PolicyEntry
}

type PolicyEntry struct {
	Target string
	Tags   []PolicyTag
	Policy string
}

type PolicyTag struct {
	Name   string
	Values []string
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
	httpPort  chan int
	config    IpAuthConfig
	allowlist []netip.Prefix
	blocklist []netip.Prefix
	etag      string
}

func (s *ExtAuthzServer) isAllowed(extIp string) bool {
	ip, err := netip.ParseAddr(extIp)
	if err != nil {
		log.Printf("Failed to parse IP: %v", err)
		return false
	}
	// allow list takes precedence over the block list
	for _, p := range s.allowlist {
		if p.Contains(ip) {
			return true
		}
	}
	for _, p := range s.blocklist {
		if p.Contains(ip) {
			return false
		}
	}
	// if there are no rules then allow
	return true
}

func (s *ExtAuthzServer) refreshPolicies(interval int) {
	if s.config.UsePolicyFile {
		err := s.readPolicyFile(*policyFile)
		if err != nil {
			log.Printf("Error during policy read: %v", err)
		}
	}
	if s.config.UsePolicyUrl {
		err := s.fetchPolicies()
		if err != nil {
			log.Printf("Error during policy fetch: %v", err)
		}
	}
	if interval > 0 {
		log.Printf("Refreshing policies every %v seconds", interval)
		for range time.Tick(time.Duration(interval) * time.Second) {
			if s.config.UsePolicyFile {
				err := s.readPolicyFile(*policyFile)
				if err != nil {
					log.Printf("Error during policy read: %v", err)
				}
			}
			if s.config.UsePolicyUrl {
				err := s.fetchPolicies()
				if err != nil {
					log.Printf("Error during policy fetch: %v", err)
				}
			}
		}
	} else {
		log.Printf("Policy refresh is disabled")
	}
}

func (s *ExtAuthzServer) applyPolicies(policies []Policy) {
	var allowlist, blocklist []netip.Prefix
	for _, policy := range policies {
		log.Printf("Applying policy ID %v, version %v, project %v", policy.Id, policy.PolicyVersion, policy.ProjectID)
		for _, policyEntry := range policy.Entries {
			p, err := netip.ParsePrefix(policyEntry.Target)
			if err != nil {
				log.Printf("Failed to parse network: %v", err)
			}
			if policyEntry.Policy == "BLOCK" {
				blocklist = append(blocklist, p)
			} else if policyEntry.Policy == "ALLOW" {
				allowlist = append(allowlist, p)
			} else {
				log.Printf("Unknown policy %v for target %v, ignoring", policyEntry.Policy, policyEntry.Target)
			}
		}
	}
	s.allowlist = allowlist
	s.blocklist = blocklist
	log.Printf("Number of network ranges: allowed: %v, blocked: %v", len(s.allowlist), len(s.blocklist))
}

func (s *ExtAuthzServer) fetchPolicies() error {
	log.Printf("Fetching policies from %s", s.config.PolicyURL)
	cfg := clientcredentials.Config{
		ClientID:     s.config.ClientId,
		ClientSecret: s.config.ClientSecret,
		TokenURL:     s.config.TokenURL,
	}
	client := cfg.Client(context.Background())

	req, _ := http.NewRequest("GET", s.config.PolicyURL, nil)
	if s.etag != "" {
		req.Header.Set("if-none-match", s.etag)
	}
	res, err := client.Do(req)
	if err != nil {
		return fmt.Errorf("failed to get policies: %w", err)
	} else if res.StatusCode == 304 {
		log.Printf("Policy with etag %v is already applied", s.etag)
		return nil
	} else if res.StatusCode == 200 {
		etag := res.Header.Get("etag")
		log.Printf("Received policy list with etag: %v", etag)

		resBody, err := io.ReadAll(res.Body)
		defer res.Body.Close()
		if err != nil {
			return fmt.Errorf("failed to read response body: %w", err)
		}
		var policies []Policy
		err = json.Unmarshal(resBody, &policies)
		if err != nil {
			return fmt.Errorf("failed to parse policies: %w", err)
		} else {
			s.applyPolicies(policies)
			s.etag = etag
			return nil
		}
	} else {
		return fmt.Errorf("failed to get policies, status code: %v", res.StatusCode)
	}
}

// ServeHTTP implements the HTTP check request.
func (s *ExtAuthzServer) ServeHTTP(response http.ResponseWriter, request *http.Request) {
	_, err := io.ReadAll(request.Body)
	if err != nil {
		log.Printf("[HTTP] read body failed: %v", err)
	}
	extIp := request.Header.Get("x-envoy-external-address")
	l := fmt.Sprintf("%s %s%s, ip: %v\n", request.Method, request.Host, request.URL, extIp)
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

func NewExtAuthzServer(config IpAuthConfig, allow []netip.Prefix, block []netip.Prefix) *ExtAuthzServer {
	return &ExtAuthzServer{
		httpPort:  make(chan int, 1),
		config:    config,
		allowlist: allow,
		blocklist: block,
	}
}

func (s *ExtAuthzServer) readPolicyFile(policyFile string) error {
	log.Printf("Reading policies from %s", policyFile)

	policiesJson, err := os.ReadFile(policyFile)
	if err != nil {
		return err
	}

	var policies []Policy
	err = json.Unmarshal(policiesJson, &policies)
	if err != nil {
		return err
	}

	s.applyPolicies(policies)
	return nil
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

	config := IpAuthConfig{UsePolicyFile: true, UsePolicyUrl: false, PolicyUpdateInterval: 600}
	var allow, block []netip.Prefix

	if *configFile != "" {
		readConfigFile(*configFile, &config)
	}

	s := NewExtAuthzServer(config, allow, block)

	go s.refreshPolicies(config.PolicyUpdateInterval)

	go s.run(fmt.Sprintf(":%s", *httpPort))
	defer s.stop()

	// Wait for the process to be shutdown.
	sigs := make(chan os.Signal, 1)
	signal.Notify(sigs, syscall.SIGINT, syscall.SIGTERM)
	<-sigs
}
