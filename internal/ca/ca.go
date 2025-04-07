package ca

import (
	"bytes"
	"crypto/rand"
	"crypto/rsa"
	"crypto/sha1"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/pem"
	"fmt"
	"log"
	"math/big"
	"sync"
	"time"

	"github.com/BitBloomLabs/simplecert/internal/config"
	"github.com/BitBloomLabs/simplecert/internal/storage"
)

// Service represents the CA service.
type Service struct {
	config       *config.Config
	storage      storage.Storage
	caKey        *rsa.PrivateKey
	caCert       *x509.Certificate
	initialized  bool
	revokedCerts sync.Map // In-memory storage for revoked certificates (serial -> time)
}

// New creates a new CA service and initializes the CA if needed.
func New(cfg *config.Config, store storage.Storage) (*Service, error) {
	s := &Service{
		config:       cfg,
		storage:      store,
		revokedCerts: sync.Map{},
	}

	err := s.initializeCA()
	if err != nil {
		return nil, fmt.Errorf("failed to initialize CA: %w", err)
	}
	s.initialized = true
	return s, nil
}

func (s *Service) initializeCA() error {
	caCertBytes, err := s.storage.GetCACertificate()
	if err == nil && len(caCertBytes) > 0 {
		block, _ := pem.Decode(caCertBytes)
		if block == nil || block.Type != "CERTIFICATE" {
			return fmt.Errorf("failed to decode CA certificate from storage")
		}
		s.caCert, err = x509.ParseCertificate(block.Bytes)
		if err != nil {
			return fmt.Errorf("failed to parse CA certificate: %w", err)
		}

		caKeyBytes, err := s.storage.GetCAPrivateKey()
		if err == nil && len(caKeyBytes) > 0 {
			block, _ = pem.Decode(caKeyBytes)
			if block == nil || block.Type != "RSA PRIVATE KEY" {
				return fmt.Errorf("failed to decode CA private key from storage")
			}
			s.caKey, err = x509.ParsePKCS1PrivateKey(block.Bytes)
			if err != nil {
				return fmt.Errorf("failed to parse CA private key: %w", err)
			}
			log.Println("Loaded existing CA key and certificate from storage.")
			return nil
		}
		log.Println("Found CA certificate in storage but not the private key. Generating a new key...")
	} else {
		log.Println("No existing CA key or certificate found. Generating a new CA...")
	}

	return s.generateAndStoreCA()
}

func (s *Service) generateAndStoreCA() error {
	privKey, err := rsa.GenerateKey(rand.Reader, 2048)
	if err != nil {
		return fmt.Errorf("failed to generate CA private key: %w", err)
	}
	s.caKey = privKey

	serialNumberLimit := new(big.Int).Lsh(big.NewInt(1), 128)
	serialNumber, err := rand.Int(rand.Reader, serialNumberLimit)
	if err != nil {
		return fmt.Errorf("failed to generate CA serial number: %w", err)
	}

	subject := pkix.Name{
		Organization: []string{s.config.Organization},
		Country:      []string{s.config.Country},
		Province:     []string{s.config.Province},
		Locality:     []string{s.config.Locality},
		CommonName:   s.config.CommonName,
	}

	template := x509.Certificate{
		SerialNumber:          serialNumber,
		Subject:               subject,
		Issuer:                subject,
		NotBefore:             time.Now(),
		NotAfter:              time.Now().AddDate(s.config.CACertValidityYears, 0, 0),
		KeyUsage:              x509.KeyUsageCertSign | x509.KeyUsageCRLSign,
		BasicConstraintsValid: true,
		IsCA:                  true,
		SubjectKeyId:          generateSubjectKeyID(&privKey.PublicKey), // Add Subject Key Identifier
	}

	derBytes, err := x509.CreateCertificate(rand.Reader, &template, &template, &privKey.PublicKey, privKey)
	if err != nil {
		return fmt.Errorf("failed to create CA certificate: %w", err)
	}
	s.caCert, err = x509.ParseCertificate(derBytes)
	if err != nil {
		return fmt.Errorf("failed to parse generated CA certificate: %w", err)
	}

	// Store the CA key and certificate
	err = s.storeCA(privKey, s.caCert)
	if err != nil {
		return fmt.Errorf("failed to store CA key and certificate: %w", err)
	}

	log.Println("Generated and stored a new CA key and certificate.")
	return nil
}

func (s *Service) storeCA(privKey *rsa.PrivateKey, cert *x509.Certificate) error {
	privKeyBytes := x509.MarshalPKCS1PrivateKey(privKey)
	privKeyPEM := pem.EncodeToMemory(&pem.Block{
		Type:  "RSA PRIVATE KEY",
		Bytes: privKeyBytes,
	})

	certBytes := cert.Raw
	certPEM := pem.EncodeToMemory(&pem.Block{
		Type:  "CERTIFICATE",
		Bytes: certBytes,
	})

	err := s.storage.SaveCAPrivateKey(privKeyPEM)
	if err != nil {
		return fmt.Errorf("failed to save CA private key: %w", err)
	}
	err = s.storage.SaveCACertificate(certPEM)
	if err != nil {
		return fmt.Errorf("failed to save CA certificate: %w", err)
	}
	return nil
}

// RevokeCertificate revokes a certificate with the given serial number.
func (s *Service) RevokeCertificate(serialNumber string) error {
	s.revokedCerts.Store(serialNumber, time.Now())
	log.Printf("Certificate with serial number %s has been revoked.", serialNumber)
	// In a real-world scenario, you might want to persist this revocation immediately.
	return nil
}

// GenerateCRL generates a Certificate Revocation List.
func (s *Service) GenerateCRL() ([]byte, error) {
	var revokedList []pkix.RevokedCertificate

	s.revokedCerts.Range(func(key, value interface{}) bool {
		serial, ok := key.(string)
		if !ok {
			log.Printf("Warning: Invalid key type in revokedCerts: %T, skipping", key)
			return true // Continue iteration
		}
		revocationTime, ok := value.(time.Time)
		if !ok {
			log.Printf("Warning: Invalid value type in revokedCerts for %s: %T, skipping", serial, value)
			return true // Continue iteration
		}

		serialNumber := new(big.Int)
		serialNumber.SetString(serial, 10) // Assuming serial numbers are stored as base-10 strings

		revokedList = append(revokedList, pkix.RevokedCertificate{
			SerialNumber:   serialNumber,
			RevocationTime: revocationTime,
		})
		return true
	})

	revocationList := &x509.RevocationList{
		Number:              big.NewInt(1), // Increment this for each new CRL
		ThisUpdate:          time.Now(),
		NextUpdate:          time.Now().Add(time.Duration(s.config.CRLValidityHours) * time.Hour),
		RevokedCertificates: revokedList,
	}

	crlBytes, err := x509.CreateRevocationList(rand.Reader, revocationList, s.caCert, s.caKey)
	if err != nil {
		return nil, fmt.Errorf("failed to create CRL: %w", err)
	}

	// Store the generated CRL
	err = s.storage.SaveCRL(crlBytes)
	if err != nil {
		log.Printf("Error saving CRL to storage: %v", err)
		// Non-fatal error, we can still serve the CRL.
	}

	return crlBytes, nil
}

// GetCACertificate returns the CA certificate.
func (s *Service) GetCACertificate() *x509.Certificate {
	return s.caCert
}

// GetCAPublicKey returns the CA public key.
func (s *Service) GetCAPublicKey() *rsa.PublicKey {
	return &s.caKey.PublicKey
}

// IsInitialized returns the initialization status of the CA.
func (s *Service) IsInitialized() bool {
	return s.initialized
}

// SignCertificate takes a PEM-encoded CSR, validates it, signs it, and returns the PEM-encoded certificate.
func (s *Service) SignCertificate(csrPEM []byte) ([]byte, error) {
	block, _ := pem.Decode(csrPEM)
	if block == nil || block.Type != "CERTIFICATE REQUEST" {
		return nil, fmt.Errorf("failed to decode PEM encoded certificate request")
	}

	csr, err := x509.ParseCertificateRequest(block.Bytes)
	if err != nil {
		return nil, fmt.Errorf("failed to parse certificate request: %w", err)
	}

	if err := csr.CheckSignature(); err != nil {
		return nil, fmt.Errorf("invalid certificate request signature: %w", err)
	}

	serialNumberLimit := new(big.Int).Lsh(big.NewInt(1), 128)
	serialNumber, err := rand.Int(rand.Reader, serialNumberLimit)
	if err != nil {
		return nil, fmt.Errorf("failed to generate serial number: %w", err)
	}

	template := x509.Certificate{
		SerialNumber:       serialNumber,
		Subject:            csr.Subject,
		Issuer:             s.caCert.Subject,
		NotBefore:          time.Now(),
		NotAfter:           time.Now().AddDate(s.config.DefaultCertValidityDays, 0, 0), // Assuming you'll add this to config
		PublicKey:          csr.PublicKey,
		SignatureAlgorithm: csr.SignatureAlgorithm,
		SubjectKeyId:       generateSubjectKeyID(csr.PublicKey),
		AuthorityKeyId:     s.caCert.SubjectKeyId,
		// BasicConstraintsValid and IsCA will depend on the type of certificate being signed.
		// For now, let's assume we are signing end-entity certificates.
		BasicConstraintsValid: true,
		IsCA:                  false,
		KeyUsage:              x509.KeyUsageDigitalSignature | x509.KeyUsageKeyEncipherment,               // Basic usage
		ExtKeyUsage:           []x509.ExtKeyUsage{x509.ExtKeyUsageServerAuth, x509.ExtKeyUsageClientAuth}, // Common extended usages
	}

	derBytes, err := x509.CreateCertificate(rand.Reader, &template, s.caCert, csr.PublicKey, s.caKey)
	if err != nil {
		return nil, fmt.Errorf("failed to create certificate: %w", err)
	}

	certPEM := new(bytes.Buffer)
	pem.Encode(certPEM, &pem.Block{
		Type:  "CERTIFICATE",
		Bytes: derBytes,
	})

	// Store the issued certificate
	err = s.storage.SaveCertificate(serialNumber.String(), derBytes)
	if err != nil {
		log.Printf("Error saving issued certificate: %v", err)
		// We don't want to fail the signing if storage fails, but we should log it.
	}

	return certPEM.Bytes(), nil
}

// generateSubjectKeyID generates a Subject Key Identifier for the given public key.
func generateSubjectKeyID(pub interface{}) (ski []byte) {
	var spkiASN1 []byte
	switch pub := pub.(type) {
	case *rsa.PublicKey:
		spkiASN1, _ = x509.MarshalPKIXPublicKey(pub)
	default:
		return nil // Or handle other key types
	}

	var digest = make([]byte, 20)
	h := sha1.New()
	h.Write(spkiASN1)
	digest = h.Sum(nil)
	return digest
}
