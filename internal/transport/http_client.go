package transport

import (
	"crypto/tls"
	"crypto/x509"
	"errors"
	"fmt"
	"net"
	"net/http"
	"os"
	"sync"
	"time"
)

type TLSOptions struct {
	CAFile     string
	CertFile   string
	KeyFile    string
	ServerName string
}

type fileStamp struct {
	size    int64
	modTime time.Time
}

type reloadingTLSMaterial struct {
	caFile   string
	certFile string
	keyFile  string

	mu              sync.RWMutex
	systemRoots     *x509.CertPool
	cachedRoots     *x509.CertPool
	cachedCAStamp   fileStamp
	cachedClient    *tls.Certificate
	cachedCertStamp fileStamp
	cachedKeyStamp  fileStamp
}

func NewHTTPClient(timeout time.Duration, tlsOpts TLSOptions) (*http.Client, error) {
	if timeout <= 0 {
		timeout = 10 * time.Second
	}

	baseTransport := &http.Transport{
		Proxy: http.ProxyFromEnvironment,
		DialContext: (&net.Dialer{
			Timeout:   5 * time.Second,
			KeepAlive: 30 * time.Second,
		}).DialContext,
		ForceAttemptHTTP2:     true,
		MaxIdleConns:          100,
		IdleConnTimeout:       90 * time.Second,
		TLSHandshakeTimeout:   10 * time.Second,
		ExpectContinueTimeout: 1 * time.Second,
	}

	if tlsOpts.CAFile != "" || (tlsOpts.CertFile != "" && tlsOpts.KeyFile != "") || tlsOpts.ServerName != "" {
		materials, err := newReloadingTLSMaterial(tlsOpts)
		if err != nil {
			return nil, err
		}

		tlsCfg := &tls.Config{MinVersion: tls.VersionTLS12}
		if tlsOpts.ServerName != "" {
			tlsCfg.ServerName = tlsOpts.ServerName
		}
		if tlsOpts.CAFile != "" {
			tlsCfg.InsecureSkipVerify = true
			tlsCfg.VerifyConnection = func(cs tls.ConnectionState) error {
				serverName := tlsOpts.ServerName
				if serverName == "" {
					serverName = cs.ServerName
				}
				return materials.verifyServerConnection(cs, serverName)
			}
		}
		if tlsOpts.CertFile != "" || tlsOpts.KeyFile != "" {
			if tlsOpts.CertFile == "" || tlsOpts.KeyFile == "" {
				return nil, fmt.Errorf("TLS client cert and key must be provided together")
			}
			tlsCfg.GetClientCertificate = func(*tls.CertificateRequestInfo) (*tls.Certificate, error) {
				return materials.clientCertificate()
			}
			if _, err := materials.clientCertificate(); err != nil {
				return nil, err
			}
		}
		baseTransport.TLSClientConfig = tlsCfg
	}

	return &http.Client{Timeout: timeout, Transport: baseTransport}, nil
}

func newReloadingTLSMaterial(tlsOpts TLSOptions) (*reloadingTLSMaterial, error) {
	systemRoots, err := x509.SystemCertPool()
	if err != nil || systemRoots == nil {
		systemRoots = x509.NewCertPool()
	}
	m := &reloadingTLSMaterial{caFile: tlsOpts.CAFile, certFile: tlsOpts.CertFile, keyFile: tlsOpts.KeyFile, systemRoots: systemRoots}
	if tlsOpts.CAFile != "" {
		if _, err := m.rootCAs(); err != nil {
			return nil, err
		}
	}
	if tlsOpts.CertFile != "" || tlsOpts.KeyFile != "" {
		if _, err := m.clientCertificate(); err != nil {
			return nil, err
		}
	}
	return m, nil
}

func (m *reloadingTLSMaterial) rootCAs() (*x509.CertPool, error) {
	if m.caFile == "" {
		return m.systemRoots, nil
	}
	caStamp, err := statFile(m.caFile, "TLS CA file")
	if err != nil {
		return nil, err
	}
	m.mu.RLock()
	if m.cachedRoots != nil && caStamp == m.cachedCAStamp {
		roots := m.cachedRoots
		m.mu.RUnlock()
		return roots, nil
	}
	m.mu.RUnlock()
	caPEM, err := os.ReadFile(m.caFile)
	if err != nil {
		return nil, fmt.Errorf("read TLS CA file: %w", err)
	}
	roots, err := x509.SystemCertPool()
	if err != nil || roots == nil {
		roots = x509.NewCertPool()
	}
	if ok := roots.AppendCertsFromPEM(caPEM); !ok {
		return nil, fmt.Errorf("append TLS CA certs: invalid PEM")
	}
	m.mu.Lock()
	m.cachedRoots = roots
	m.cachedCAStamp = caStamp
	m.mu.Unlock()
	return roots, nil
}

func (m *reloadingTLSMaterial) clientCertificate() (*tls.Certificate, error) {
	certStamp, err := statFile(m.certFile, "TLS client certificate")
	if err != nil {
		return m.cachedClientOr(err)
	}
	keyStamp, err := statFile(m.keyFile, "TLS client key")
	if err != nil {
		return m.cachedClientOr(err)
	}
	m.mu.RLock()
	if m.cachedClient != nil && certStamp == m.cachedCertStamp && keyStamp == m.cachedKeyStamp {
		cert := m.cachedClient
		m.mu.RUnlock()
		return cert, nil
	}
	m.mu.RUnlock()
	crt, err := tls.LoadX509KeyPair(m.certFile, m.keyFile)
	if err != nil {
		return m.cachedClientOr(fmt.Errorf("load TLS client certificate: %w", err))
	}
	m.mu.Lock()
	m.cachedClient = &crt
	m.cachedCertStamp = certStamp
	m.cachedKeyStamp = keyStamp
	m.mu.Unlock()
	return &crt, nil
}

func (m *reloadingTLSMaterial) cachedClientOr(err error) (*tls.Certificate, error) {
	m.mu.RLock()
	cached := m.cachedClient
	m.mu.RUnlock()
	if cached != nil {
		return cached, nil
	}
	return nil, err
}

func (m *reloadingTLSMaterial) verifyServerConnection(cs tls.ConnectionState, serverName string) error {
	if len(cs.PeerCertificates) == 0 {
		return errors.New("TLS server certificate missing from peer")
	}
	roots, err := m.rootCAs()
	if err != nil {
		return err
	}
	intermediates := x509.NewCertPool()
	for _, cert := range cs.PeerCertificates[1:] {
		intermediates.AddCert(cert)
	}
	_, err = cs.PeerCertificates[0].Verify(x509.VerifyOptions{DNSName: serverName, Roots: roots, Intermediates: intermediates, CurrentTime: time.Now(), KeyUsages: []x509.ExtKeyUsage{x509.ExtKeyUsageServerAuth}})
	if err != nil {
		return fmt.Errorf("verify TLS server certificate: %w", err)
	}
	return nil
}

func statFile(path string, label string) (fileStamp, error) {
	if path == "" {
		return fileStamp{}, nil
	}
	info, err := os.Stat(path)
	if err != nil {
		if errors.Is(err, os.ErrNotExist) {
			return fileStamp{}, fmt.Errorf("%s does not exist: %s", label, path)
		}
		return fileStamp{}, fmt.Errorf("stat %s: %w", label, err)
	}
	return fileStamp{size: info.Size(), modTime: info.ModTime().UTC()}, nil
}
