package server

import (
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/sha256"
	"crypto/tls"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/hex"
	"encoding/pem"
	"math/big"
	"net"
	"os"
	"path/filepath"
	"time"
)

// loadOrCreateCert returns the configured certificate or creates a
// self-signed ECDSA one in the data directory on first start. Agents pin its
// SHA-256 fingerprint at enrollment (trust on first use).
func loadOrCreateCert(certFile, keyFile, dataDir string) (tls.Certificate, string, error) {
	if certFile == "" {
		certFile, keyFile = filepath.Join(dataDir, "manager.crt"), filepath.Join(dataDir, "manager.key")
		if _, err := os.Stat(certFile); os.IsNotExist(err) {
			if err := genCert(certFile, keyFile); err != nil {
				return tls.Certificate{}, "", err
			}
		}
	}
	cert, err := tls.LoadX509KeyPair(certFile, keyFile)
	if err != nil {
		return cert, "", err
	}
	sum := sha256.Sum256(cert.Certificate[0])
	return cert, hex.EncodeToString(sum[:]), nil
}

func genCert(certFile, keyFile string) error {
	key, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		return err
	}
	serial, _ := rand.Int(rand.Reader, new(big.Int).Lsh(big.NewInt(1), 120))
	host, _ := os.Hostname()
	tpl := &x509.Certificate{
		SerialNumber: serial,
		Subject:      pkix.Name{CommonName: "warden-manager", Organization: []string{"warden-xdr"}},
		NotBefore:    time.Now().Add(-time.Hour),
		NotAfter:     time.Now().AddDate(10, 0, 0),
		KeyUsage:     x509.KeyUsageDigitalSignature,
		ExtKeyUsage:  []x509.ExtKeyUsage{x509.ExtKeyUsageServerAuth},
		DNSNames:     []string{"localhost", host, "warden-manager"},
		IPAddresses:  []net.IP{net.ParseIP("127.0.0.1"), net.ParseIP("::1")},
	}
	der, err := x509.CreateCertificate(rand.Reader, tpl, tpl, &key.PublicKey, key)
	if err != nil {
		return err
	}
	kb, err := x509.MarshalECPrivateKey(key)
	if err != nil {
		return err
	}
	if err := os.WriteFile(certFile, pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: der}), 0644); err != nil {
		return err
	}
	return os.WriteFile(keyFile, pem.EncodeToMemory(&pem.Block{Type: "EC PRIVATE KEY", Bytes: kb}), 0600)
}
