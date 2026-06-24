package pkg

import (
	"context"
	"crypto/tls"
	"crypto/x509"
	"fmt"
	"net"
	"strconv"
	"sync"
	"time"
)

// ScanTarget represents one network endpoint to collect certificate data from.
type ScanTarget struct {
	Host     string            `json:"host"`
	Port     int               `json:"port"`
	Metadata map[string]string `json:"metadata,omitempty"`
}

// Address returns the host:port representation of the target.
func (t ScanTarget) Address() string {
	port := t.Port
	if port == 0 {
		port = 443
	}
	return net.JoinHostPort(t.Host, strconv.Itoa(port))
}

// BatchScanResult is the certificate and TLS metadata collected from one target.
type BatchScanResult struct {
	Target       ScanTarget          `json:"target"`
	CertChain    []*x509.Certificate `json:"-"`
	CertChainDER [][]byte            `json:"cert_chain_der,omitempty"`
	TLSVersion   uint16              `json:"tls_version"`
	CipherSuite  uint16              `json:"cipher_suite"`
	ServerName   string              `json:"server_name,omitempty"`
	ObservedAt   time.Time           `json:"observed_at"`
	Duration     time.Duration       `json:"duration"`
	Error        error               `json:"-"`
	ErrorMessage string              `json:"error,omitempty"`
}

// BatchScanConfig controls large-scale certificate collection.
type BatchScanConfig struct {
	Concurrency   int           `json:"concurrency"`
	Timeout       time.Duration `json:"timeout"`
	RateLimit     int           `json:"rate_limit"`
	RetryCount    int           `json:"retry_count"`
	RetryDelay    time.Duration `json:"retry_delay"`
	SkipTLSVerify bool          `json:"skip_tls_verify"`
	ServerName    string        `json:"server_name,omitempty"`
}

// DefaultBatchScanConfig returns conservative defaults for Internet-facing scans.
func DefaultBatchScanConfig() BatchScanConfig {
	return BatchScanConfig{
		Concurrency:   100,
		Timeout:       5 * time.Second,
		RetryCount:    2,
		RetryDelay:    500 * time.Millisecond,
		SkipTLSVerify: true,
	}
}

// BatchScanner collects certificates from many IP:port or domain:port endpoints.
type BatchScanner struct {
	config BatchScanConfig
	limit  *scanRateLimiter
}

// NewBatchScanner creates a scanner with normalized defaults.
func NewBatchScanner(config BatchScanConfig) *BatchScanner {
	defaults := DefaultBatchScanConfig()
	if config.Concurrency <= 0 {
		config.Concurrency = defaults.Concurrency
	}
	if config.Timeout <= 0 {
		config.Timeout = defaults.Timeout
	}
	if config.RetryCount < 0 {
		config.RetryCount = defaults.RetryCount
	}
	if config.RetryDelay <= 0 {
		config.RetryDelay = defaults.RetryDelay
	}
	return &BatchScanner{
		config: config,
		limit:  newScanRateLimiter(config.RateLimit),
	}
}

// Scan collects certificates for all targets. Results keep the same order as input.
func (s *BatchScanner) Scan(ctx context.Context, targets []ScanTarget) ([]BatchScanResult, error) {
	if s.limit != nil {
		defer s.limit.stop()
	}

	results := make([]BatchScanResult, len(targets))
	jobs := make(chan int)
	var wg sync.WaitGroup

	workerCount := s.config.Concurrency
	if workerCount > len(targets) && len(targets) > 0 {
		workerCount = len(targets)
	}

	for i := 0; i < workerCount; i++ {
		wg.Add(1)
		go func() {
			defer wg.Done()
			for idx := range jobs {
				results[idx] = s.scanWithRetry(ctx, targets[idx])
			}
		}()
	}

	for i := range targets {
		select {
		case <-ctx.Done():
			close(jobs)
			wg.Wait()
			return results, ctx.Err()
		case jobs <- i:
		}
	}
	close(jobs)
	wg.Wait()

	if err := ctx.Err(); err != nil {
		return results, err
	}
	return results, nil
}

func (s *BatchScanner) scanWithRetry(ctx context.Context, target ScanTarget) BatchScanResult {
	start := time.Now()
	var last BatchScanResult

	for attempt := 0; attempt <= s.config.RetryCount; attempt++ {
		if attempt > 0 {
			select {
			case <-ctx.Done():
				return batchScanError(target, start, ctx.Err())
			case <-time.After(s.config.RetryDelay):
			}
		}
		if s.limit != nil {
			if err := s.limit.wait(ctx); err != nil {
				return batchScanError(target, start, err)
			}
		}

		last = s.scanOnce(ctx, target, start)
		if last.Error == nil {
			return last
		}
	}

	if last.Error != nil {
		last.Error = fmt.Errorf("after %d retries: %w", s.config.RetryCount, last.Error)
		last.ErrorMessage = last.Error.Error()
	}
	return last
}

func (s *BatchScanner) scanOnce(ctx context.Context, target ScanTarget, start time.Time) BatchScanResult {
	dialCtx, cancel := context.WithTimeout(ctx, s.config.Timeout)
	defer cancel()

	host := target.Host
	serverName := s.config.ServerName
	if serverName == "" && net.ParseIP(host) == nil {
		serverName = host
	}

	dialer := &tls.Dialer{
		NetDialer: &net.Dialer{Timeout: s.config.Timeout},
		Config: &tls.Config{
			ServerName:         serverName,
			InsecureSkipVerify: s.config.SkipTLSVerify,
		},
	}

	conn, err := dialer.DialContext(dialCtx, "tcp", target.Address())
	if err != nil {
		return batchScanError(target, start, err)
	}
	defer conn.Close()

	tlsConn, ok := conn.(*tls.Conn)
	if !ok {
		return batchScanError(target, start, fmt.Errorf("connection is not TLS"))
	}

	state := tlsConn.ConnectionState()
	der := make([][]byte, 0, len(state.PeerCertificates))
	for _, cert := range state.PeerCertificates {
		der = append(der, cert.Raw)
	}

	return BatchScanResult{
		Target:       target,
		CertChain:    state.PeerCertificates,
		CertChainDER: der,
		TLSVersion:   state.Version,
		CipherSuite:  state.CipherSuite,
		ServerName:   serverName,
		ObservedAt:   time.Now(),
		Duration:     time.Since(start),
	}
}

func batchScanError(target ScanTarget, start time.Time, err error) BatchScanResult {
	return BatchScanResult{
		Target:       target,
		ObservedAt:   time.Now(),
		Duration:     time.Since(start),
		Error:        err,
		ErrorMessage: err.Error(),
	}
}

type scanRateLimiter struct {
	ticker *time.Ticker
}

func newScanRateLimiter(ratePerSecond int) *scanRateLimiter {
	if ratePerSecond <= 0 {
		return nil
	}
	interval := time.Second / time.Duration(ratePerSecond)
	if interval <= 0 {
		interval = time.Nanosecond
	}
	return &scanRateLimiter{ticker: time.NewTicker(interval)}
}

func (l *scanRateLimiter) wait(ctx context.Context) error {
	select {
	case <-ctx.Done():
		return ctx.Err()
	case <-l.ticker.C:
		return nil
	}
}

func (l *scanRateLimiter) stop() {
	l.ticker.Stop()
}

// ScanFromHosts expands hosts and ports into scan targets.
func ScanFromHosts(hosts []string, ports []int) []ScanTarget {
	if len(ports) == 0 {
		ports = []int{443}
	}
	targets := make([]ScanTarget, 0, len(hosts)*len(ports))
	for _, host := range hosts {
		for _, port := range ports {
			targets = append(targets, ScanTarget{Host: host, Port: port})
		}
	}
	return targets
}

// ScanFromIPRange expands a CIDR into scan targets.
func ScanFromIPRange(cidr string, ports []int) ([]ScanTarget, error) {
	ip, ipNet, err := net.ParseCIDR(cidr)
	if err != nil {
		return nil, fmt.Errorf("invalid CIDR %q: %w", cidr, err)
	}
	if len(ports) == 0 {
		ports = []int{443}
	}

	var targets []ScanTarget
	for current := ip.Mask(ipNet.Mask); ipNet.Contains(current); current = incrementIP(current) {
		ipCopy := make(net.IP, len(current))
		copy(ipCopy, current)
		for _, port := range ports {
			targets = append(targets, ScanTarget{Host: ipCopy.String(), Port: port})
		}
	}
	return targets, nil
}

func incrementIP(ip net.IP) net.IP {
	next := make(net.IP, len(ip))
	copy(next, ip)
	for i := len(next) - 1; i >= 0; i-- {
		next[i]++
		if next[i] != 0 {
			break
		}
	}
	return next
}
