package netutil

import (
	"crypto/tls"
	"crypto/x509"
	"errors"
	"fmt"
	"net"
	"net/http"
	"os"
	"time"
)

type TLSOptions struct {
	CAFile     string
	CertFile   string
	KeyFile    string
	ServerName string
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
		rootCAs, err := x509.SystemCertPool()
		if err != nil || rootCAs == nil {
			rootCAs = x509.NewCertPool()
		}

		if tlsOpts.CAFile != "" {
			if _, statErr := os.Stat(tlsOpts.CAFile); statErr != nil {
				if errors.Is(statErr, os.ErrNotExist) {
					return nil, fmt.Errorf("TLS CA file does not exist: %s", tlsOpts.CAFile)
				}
				return nil, fmt.Errorf("stat TLS CA file: %w", statErr)
			}
			caPem, readErr := os.ReadFile(tlsOpts.CAFile)
			if readErr != nil {
				return nil, fmt.Errorf("read TLS CA file: %w", readErr)
			}
			if ok := rootCAs.AppendCertsFromPEM(caPem); !ok {
				return nil, fmt.Errorf("append TLS CA certs: invalid PEM")
			}
		}

		tlsCfg := &tls.Config{
			MinVersion: tls.VersionTLS12,
			RootCAs:    rootCAs,
		}
		if tlsOpts.ServerName != "" {
			tlsCfg.ServerName = tlsOpts.ServerName
		}

		if tlsOpts.CertFile != "" || tlsOpts.KeyFile != "" {
			if tlsOpts.CertFile == "" || tlsOpts.KeyFile == "" {
				return nil, fmt.Errorf("TLS client cert and key must be provided together")
			}
			if _, statErr := os.Stat(tlsOpts.CertFile); statErr != nil {
				if errors.Is(statErr, os.ErrNotExist) {
					return nil, fmt.Errorf("TLS client certificate does not exist: %s", tlsOpts.CertFile)
				}
				return nil, fmt.Errorf("stat TLS client certificate: %w", statErr)
			}
			if _, statErr := os.Stat(tlsOpts.KeyFile); statErr != nil {
				if errors.Is(statErr, os.ErrNotExist) {
					return nil, fmt.Errorf("TLS client key does not exist: %s", tlsOpts.KeyFile)
				}
				return nil, fmt.Errorf("stat TLS client key: %w", statErr)
			}
			crt, loadErr := tls.LoadX509KeyPair(tlsOpts.CertFile, tlsOpts.KeyFile)
			if loadErr != nil {
				return nil, fmt.Errorf("load TLS client certificate: %w", loadErr)
			}
			tlsCfg.Certificates = []tls.Certificate{crt}
		}

		baseTransport.TLSClientConfig = tlsCfg
	}

	return &http.Client{
		Timeout:   timeout,
		Transport: baseTransport,
	}, nil
}
