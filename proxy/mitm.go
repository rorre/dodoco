package proxy

import (
	"crypto/rand"
	"crypto/rsa"
	"crypto/tls"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/pem"
	"fmt"
	"math/big"
	"net"
	"os"
	"sync"
	"time"
)

type mitmConfig struct {
	ca     *x509.Certificate
	priv   *rsa.PrivateKey
	config *tls.Config
	cache  sync.Map
}

func (p *Proxy) InitMITM(caCertPath, caKeyPath string) error {
	caCertData, err := os.ReadFile(caCertPath)
	if err != nil {
		return fmt.Errorf("reading CA cert: %w", err)
	}
	caKeyData, err := os.ReadFile(caKeyPath)
	if err != nil {
		return fmt.Errorf("reading CA key: %w", err)
	}

	certBlock, _ := pem.Decode(caCertData)
	if certBlock == nil || certBlock.Type != "CERTIFICATE" {
		return fmt.Errorf("invalid CA certificate")
	}
	ca, err := x509.ParseCertificate(certBlock.Bytes)
	if err != nil {
		return fmt.Errorf("parsing CA certificate: %w", err)
	}

	keyBlock, _ := pem.Decode(caKeyData)
	if keyBlock == nil || (keyBlock.Type != "RSA PRIVATE KEY" && keyBlock.Type != "PRIVATE KEY") {
		return fmt.Errorf("invalid CA private key")
	}

	var priv *rsa.PrivateKey
	if keyBlock.Type == "RSA PRIVATE KEY" {
		priv, err = x509.ParsePKCS1PrivateKey(keyBlock.Bytes)
	} else {
		pk, err2 := x509.ParsePKCS8PrivateKey(keyBlock.Bytes)
		if err2 != nil {
			return fmt.Errorf("parsing CA private key: %w", err2)
		}
		var ok bool
		priv, ok = pk.(*rsa.PrivateKey)
		if !ok {
			return fmt.Errorf("CA private key is not RSA")
		}
	}
	if err != nil {
		return fmt.Errorf("parsing CA private key: %w", err)
	}

	p.mitm = &mitmConfig{
		ca:   ca,
		priv: priv,
	}
	return nil
}

func (p *Proxy) CheckCAInstalled() bool {
	if p.mitm == nil || p.mitm.ca == nil {
		return false
	}
	// Verify against system roots
	_, err := p.mitm.ca.Verify(x509.VerifyOptions{})
	return err == nil
}

func (p *Proxy) getCertForHost(host string) (*tls.Certificate, error) {
	if p.mitm == nil {
		return nil, fmt.Errorf("MITM not initialized")
	}

	if val, ok := p.mitm.cache.Load(host); ok {
		return val.(*tls.Certificate), nil
	}

	// Strip port if present
	hostname, _, err := net.SplitHostPort(host)
	if err != nil {
		hostname = host
	}

	serialNumberLimit := new(big.Int).Lsh(big.NewInt(1), 128)
	serialNumber, err := rand.Int(rand.Reader, serialNumberLimit)
	if err != nil {
		return nil, fmt.Errorf("failed to generate serial number: %w", err)
	}

	template := x509.Certificate{
		SerialNumber: serialNumber,
		Subject: pkix.Name{
			CommonName: hostname,
		},
		NotBefore: time.Now().Add(-24 * time.Hour),
		NotAfter:  time.Now().Add(365 * 24 * time.Hour),

		KeyUsage:              x509.KeyUsageKeyEncipherment | x509.KeyUsageDigitalSignature,
		ExtKeyUsage:           []x509.ExtKeyUsage{x509.ExtKeyUsageServerAuth},
		BasicConstraintsValid: true,
		DNSNames:              []string{hostname},
	}

	priv, err := rsa.GenerateKey(rand.Reader, 2048)
	if err != nil {
		return nil, fmt.Errorf("failed to generate private key: %w", err)
	}

	derBytes, err := x509.CreateCertificate(rand.Reader, &template, p.mitm.ca, &priv.PublicKey, p.mitm.priv)
	if err != nil {
		return nil, fmt.Errorf("failed to create certificate: %w", err)
	}

	cert := &tls.Certificate{
		Certificate: [][]byte{derBytes},
		PrivateKey:  priv,
	}

	p.mitm.cache.Store(host, cert)
	return cert, nil
}
