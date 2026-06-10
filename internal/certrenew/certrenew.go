package certrenew

import (
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/tls"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/pem"
	"errors"
	"fmt"
	"os"
	"time"

	agentcfg "gitlab.com/nathanmblima/dynasmon-seagull/agent/internal/config"
)

type CertStatus struct {
	SerialHex string
	NotBefore time.Time
	NotAfter  time.Time
}

func Inspect(certFile string) (CertStatus, error) {
	data, err := os.ReadFile(certFile)
	if err != nil {
		return CertStatus{}, fmt.Errorf("read client certificate: %w", err)
	}
	block, _ := pem.Decode(data)
	if block == nil || block.Type != "CERTIFICATE" {
		return CertStatus{}, errors.New("client certificate file is not certificate PEM")
	}
	cert, err := x509.ParseCertificate(block.Bytes)
	if err != nil {
		return CertStatus{}, fmt.Errorf("parse client certificate: %w", err)
	}
	return CertStatus{
		SerialHex: cert.SerialNumber.Text(16),
		NotBefore: cert.NotBefore,
		NotAfter:  cert.NotAfter,
	}, nil
}

func NeedsRenewal(certFile string, renewBefore time.Duration, now time.Time) (bool, CertStatus, error) {
	status, err := Inspect(certFile)
	if err != nil {
		return false, CertStatus{}, err
	}
	if renewBefore <= 0 {
		renewBefore = 30 * 24 * time.Hour
	}
	return !status.NotAfter.After(now.Add(renewBefore)), status, nil
}

func NewKeyAndCSR(agentID string) ([]byte, []byte, error) {
	key, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		return nil, nil, fmt.Errorf("generate key: %w", err)
	}
	csrDER, err := x509.CreateCertificateRequest(rand.Reader, &x509.CertificateRequest{
		Subject: pkix.Name{
			CommonName:   agentID,
			Organization: []string{"Seagull Agents"},
		},
	}, key)
	if err != nil {
		return nil, nil, fmt.Errorf("create certificate request: %w", err)
	}
	keyDER, err := x509.MarshalECPrivateKey(key)
	if err != nil {
		return nil, nil, fmt.Errorf("marshal key: %w", err)
	}
	keyPEM := pem.EncodeToMemory(&pem.Block{Type: "EC PRIVATE KEY", Bytes: keyDER})
	csrPEM := pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE REQUEST", Bytes: csrDER})
	return keyPEM, csrPEM, nil
}

func PersistPair(certPEM, keyPEM []byte, certFile, keyFile string) error {
	if _, err := tls.X509KeyPair(certPEM, keyPEM); err != nil {
		return fmt.Errorf("issued certificate does not match generated key: %w", err)
	}
	if err := agentcfg.AtomicWriteFile(keyFile, keyPEM, 0o600); err != nil {
		return fmt.Errorf("persist client key: %w", err)
	}
	if err := agentcfg.AtomicWriteFile(certFile, certPEM, 0o644); err != nil {
		return fmt.Errorf("persist client certificate: %w", err)
	}
	return nil
}
