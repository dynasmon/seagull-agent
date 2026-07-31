package certrenew

import (
	"bytes"
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
	"path/filepath"
	"strings"
	"sync"
	"time"

	agentcfg "github.com/dynasmon/seagull-agent/internal/config"
)

var pairMu sync.Mutex

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

func PersistServerCA(bundlePEM string, caFile string) (bool, error) {
	bundle := strings.TrimSpace(bundlePEM)
	target := strings.TrimSpace(caFile)
	if bundle == "" || target == "" {
		return false, nil
	}
	if err := ValidateServerCA(bundle); err != nil {
		return false, err
	}
	if existing, err := os.ReadFile(target); err == nil && strings.TrimSpace(string(existing)) == bundle {
		return false, nil
	}
	if err := agentcfg.AtomicWriteFile(target, []byte(bundle+"\n"), 0o644); err != nil {
		return false, fmt.Errorf("persist server CA: %w", err)
	}
	return true, nil
}

func ValidateServerCA(bundlePEM string) error {
	bundle := strings.TrimSpace(bundlePEM)
	if bundle == "" {
		return errors.New("server CA bundle is empty")
	}
	remaining := []byte(bundle)
	certificates := 0
	for len(bytes.TrimSpace(remaining)) > 0 {
		block, rest := pem.Decode(remaining)
		if block == nil || block.Type != "CERTIFICATE" {
			return errors.New("server CA bundle is not certificate PEM")
		}
		certificate, err := x509.ParseCertificate(block.Bytes)
		if err != nil {
			return fmt.Errorf("parse server CA bundle: %w", err)
		}
		if !certificate.BasicConstraintsValid || !certificate.IsCA {
			return errors.New("server CA bundle contains a non-CA certificate")
		}
		certificates++
		remaining = rest
	}
	if certificates == 0 {
		return errors.New("server CA bundle does not contain certificates")
	}
	return nil
}

func ValidateIssuedPair(certPEM, keyPEM []byte, agentID string, now time.Time) (CertStatus, error) {
	expectedAgentID := strings.TrimSpace(agentID)
	if expectedAgentID == "" {
		return CertStatus{}, errors.New("expected agent identity is required")
	}
	pair, err := tls.X509KeyPair(certPEM, keyPEM)
	if err != nil {
		return CertStatus{}, fmt.Errorf("issued certificate does not match generated key: %w", err)
	}
	if len(pair.Certificate) == 0 {
		return CertStatus{}, errors.New("issued certificate chain is empty")
	}
	certificate, err := x509.ParseCertificate(pair.Certificate[0])
	if err != nil {
		return CertStatus{}, fmt.Errorf("parse issued client certificate: %w", err)
	}
	if strings.TrimSpace(certificate.Subject.CommonName) != expectedAgentID {
		return CertStatus{}, errors.New("issued certificate identity does not match the agent")
	}
	if certificate.IsCA {
		return CertStatus{}, errors.New("issued client certificate cannot be a CA")
	}
	if now.IsZero() {
		now = time.Now().UTC()
	}
	now = now.UTC()
	if now.Before(certificate.NotBefore) || !now.Before(certificate.NotAfter) {
		return CertStatus{}, errors.New("issued client certificate is not currently valid")
	}
	clientAuth := false
	for _, usage := range certificate.ExtKeyUsage {
		if usage == x509.ExtKeyUsageClientAuth || usage == x509.ExtKeyUsageAny {
			clientAuth = true
			break
		}
	}
	if !clientAuth {
		return CertStatus{}, errors.New("issued certificate does not allow client authentication")
	}
	return CertStatus{
		SerialHex: certificate.SerialNumber.Text(16),
		NotBefore: certificate.NotBefore,
		NotAfter:  certificate.NotAfter,
	}, nil
}

func PersistPair(certPEM, keyPEM []byte, agentID, certFile, keyFile string) error {
	pairMu.Lock()
	defer pairMu.Unlock()

	if _, err := ValidateIssuedPair(certPEM, keyPEM, agentID, time.Now().UTC()); err != nil {
		return err
	}
	certFile = strings.TrimSpace(certFile)
	keyFile = strings.TrimSpace(keyFile)
	if certFile == "" || keyFile == "" {
		return errors.New("client certificate and key paths are required")
	}
	if certFile == keyFile {
		return errors.New("client certificate and key paths must be different")
	}
	if err := recoverPair(certFile, keyFile); err != nil {
		return fmt.Errorf("recover previous certificate transaction: %w", err)
	}

	certNext := certFile + ".next"
	keyNext := keyFile + ".next"
	certPrevious := certFile + ".previous"
	keyPrevious := keyFile + ".previous"
	transaction := certFile + ".pair-transaction"

	if err := agentcfg.AtomicWriteFile(keyNext, keyPEM, 0o600); err != nil {
		return fmt.Errorf("stage client key: %w", err)
	}
	if err := agentcfg.AtomicWriteFile(certNext, certPEM, 0o644); err != nil {
		os.Remove(keyNext)
		return fmt.Errorf("stage client certificate: %w", err)
	}
	if err := agentcfg.AtomicWriteFile(transaction, []byte(time.Now().UTC().Format(time.RFC3339Nano)), 0o600); err != nil {
		os.Remove(keyNext)
		os.Remove(certNext)
		return fmt.Errorf("start certificate transaction: %w", err)
	}

	commit := func() error {
		if err := replaceBackup(keyFile, keyPrevious); err != nil {
			return err
		}
		if err := replaceBackup(certFile, certPrevious); err != nil {
			return err
		}
		if err := os.Rename(keyNext, keyFile); err != nil {
			return fmt.Errorf("commit client key: %w", err)
		}
		if err := syncDirectory(filepath.Dir(keyFile)); err != nil {
			return err
		}
		if err := os.Rename(certNext, certFile); err != nil {
			return fmt.Errorf("commit client certificate: %w", err)
		}
		if err := syncDirectory(filepath.Dir(certFile)); err != nil {
			return err
		}
		if _, err := tls.LoadX509KeyPair(certFile, keyFile); err != nil {
			return fmt.Errorf("validate committed certificate pair: %w", err)
		}
		return nil
	}

	if err := commit(); err != nil {
		recoveryErr := recoverPair(certFile, keyFile)
		return errors.Join(fmt.Errorf("commit certificate transaction: %w", err), recoveryErr)
	}
	return cleanupPairArtifacts(certFile, keyFile)
}

func RecoverPair(certFile string, keyFile string) error {
	pairMu.Lock()
	defer pairMu.Unlock()
	return recoverPair(certFile, keyFile)
}

func recoverPair(certFile string, keyFile string) error {
	certFile = strings.TrimSpace(certFile)
	keyFile = strings.TrimSpace(keyFile)
	if certFile == "" || keyFile == "" {
		return nil
	}
	if _, err := tls.LoadX509KeyPair(certFile, keyFile); err == nil {
		return cleanupPairArtifacts(certFile, keyFile)
	}

	certCurrent := readOptional(certFile)
	keyCurrent := readOptional(keyFile)
	certNext := readOptional(certFile + ".next")
	keyNext := readOptional(keyFile + ".next")
	certPrevious := readOptional(certFile + ".previous")
	keyPrevious := readOptional(keyFile + ".previous")

	candidates := []struct {
		cert []byte
		key  []byte
	}{
		{cert: certCurrent, key: keyPrevious},
		{cert: certPrevious, key: keyPrevious},
		{cert: certNext, key: keyCurrent},
		{cert: certNext, key: keyNext},
		{cert: certPrevious, key: keyCurrent},
	}
	for _, candidate := range candidates {
		if len(candidate.cert) == 0 || len(candidate.key) == 0 {
			continue
		}
		if _, err := tls.X509KeyPair(candidate.cert, candidate.key); err != nil {
			continue
		}
		if err := agentcfg.AtomicWriteFile(keyFile, candidate.key, 0o600); err != nil {
			return fmt.Errorf("restore client key: %w", err)
		}
		if err := agentcfg.AtomicWriteFile(certFile, candidate.cert, 0o644); err != nil {
			return fmt.Errorf("restore client certificate: %w", err)
		}
		return cleanupPairArtifacts(certFile, keyFile)
	}

	if len(certCurrent) == 0 && len(keyCurrent) == 0 &&
		len(certNext) == 0 && len(keyNext) == 0 &&
		len(certPrevious) == 0 && len(keyPrevious) == 0 {
		return nil
	}
	return errors.New("no valid client certificate transaction state could be recovered")
}

func replaceBackup(current string, previous string) error {
	if err := os.Remove(previous); err != nil && !errors.Is(err, os.ErrNotExist) {
		return fmt.Errorf("remove stale certificate backup: %w", err)
	}
	if err := os.Rename(current, previous); err != nil {
		if errors.Is(err, os.ErrNotExist) {
			return nil
		}
		return fmt.Errorf("backup certificate material: %w", err)
	}
	return syncDirectory(filepath.Dir(current))
}

func cleanupPairArtifacts(certFile string, keyFile string) error {
	paths := []string{
		certFile + ".next",
		keyFile + ".next",
		certFile + ".previous",
		keyFile + ".previous",
		certFile + ".pair-transaction",
	}
	var cleanupErr error
	for _, path := range paths {
		if err := os.Remove(path); err != nil && !errors.Is(err, os.ErrNotExist) {
			cleanupErr = errors.Join(cleanupErr, err)
		}
	}
	for _, dir := range uniqueDirectories(paths) {
		cleanupErr = errors.Join(cleanupErr, syncDirectory(dir))
	}
	if cleanupErr != nil {
		return fmt.Errorf("clean certificate transaction: %w", cleanupErr)
	}
	return nil
}

func readOptional(path string) []byte {
	data, err := os.ReadFile(path)
	if err != nil {
		return nil
	}
	return data
}

func uniqueDirectories(paths []string) []string {
	seen := make(map[string]struct{})
	out := make([]string, 0, len(paths))
	for _, path := range paths {
		dir := filepath.Dir(path)
		if _, ok := seen[dir]; ok {
			continue
		}
		seen[dir] = struct{}{}
		out = append(out, dir)
	}
	return out
}

func syncDirectory(path string) error {
	dir, err := os.Open(path)
	if err != nil {
		if errors.Is(err, os.ErrNotExist) {
			return nil
		}
		return fmt.Errorf("open certificate directory: %w", err)
	}
	syncErr := dir.Sync()
	closeErr := dir.Close()
	if syncErr != nil {
		return fmt.Errorf("sync certificate directory: %w", syncErr)
	}
	if closeErr != nil {
		return fmt.Errorf("close certificate directory: %w", closeErr)
	}
	return nil
}
