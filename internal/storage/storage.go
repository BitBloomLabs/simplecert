package storage

import (
	"os"
	"path/filepath"
	"time"
)

// Storage is an interface for storing and retrieving CA data.
type Storage interface {
	SaveCertificate(serial string, certBytes []byte) error
	GetCertificate(serial string) ([]byte, error)
	SaveCRL(crlBytes []byte) error
	GetLatestCRL() ([]byte, error)
	SaveCAPrivateKey(keyBytes []byte) error
	GetCAPrivateKey() ([]byte, error)
	SaveCACertificate(certBytes []byte) error
	GetCACertificate() ([]byte, error)
	// Methods for revoked certificates (placeholders for now)
	SaveRevokedCertificate(serial string, revocationTime time.Time) error
	GetRevokedCertificates() (map[string]time.Time, error)
	// Add other storage methods as needed
}

// FileStorage is a basic file-based storage implementation.
type FileStorage struct {
	dataDir string
}

// NewFileStorage creates a new FileStorage instance.
func NewFileStorage(dataDir string) (*FileStorage, error) {
	err := os.MkdirAll(filepath.Join(dataDir, "certs"), 0755)
	if err != nil {
		return nil, err
	}
	err = os.MkdirAll(filepath.Join(dataDir, "crl"), 0755)
	if err != nil {
		return nil, err
	}
	err = os.MkdirAll(filepath.Join(dataDir, "ca"), 0755)
	if err != nil {
		return nil, err
	}
	return &FileStorage{dataDir: dataDir}, nil
}

// SaveCertificate saves a certificate to a file.
func (fs *FileStorage) SaveCertificate(serial string, certBytes []byte) error {
	filename := filepath.Join(fs.dataDir, "certs", serial+".crt")
	return os.WriteFile(filename, certBytes, 0644)
}

// GetCertificate retrieves a certificate from a file.
func (fs *FileStorage) GetCertificate(serial string) ([]byte, error) {
	filename := filepath.Join(fs.dataDir, "certs", serial+".crt")
	return os.ReadFile(filename)
}

// SaveCRL saves the CRL to a file.
func (fs *FileStorage) SaveCRL(crlBytes []byte) error {
	filename := filepath.Join(fs.dataDir, "crl", "crl.pem")
	return os.WriteFile(filename, crlBytes, 0644)
}

// GetLatestCRL retrieves the latest CRL from a file.
func (fs *FileStorage) GetLatestCRL() ([]byte, error) {
	filename := filepath.Join(fs.dataDir, "crl", "crl.pem")
	return os.ReadFile(filename)
}

// SaveCAPrivateKey saves the CA's private key to a file.
func (fs *FileStorage) SaveCAPrivateKey(keyBytes []byte) error {
	filename := filepath.Join(fs.dataDir, "ca", "ca.key")
	return os.WriteFile(filename, keyBytes, 0600) // Sensitive data, restrict permissions
}

// GetCAPrivateKey retrieves the CA's private key from a file.
func (fs *FileStorage) GetCAPrivateKey() ([]byte, error) {
	filename := filepath.Join(fs.dataDir, "ca", "ca.key")
	return os.ReadFile(filename)
}

// SaveCACertificate saves the CA's certificate to a file.
func (fs *FileStorage) SaveCACertificate(certBytes []byte) error {
	filename := filepath.Join(fs.dataDir, "ca", "ca.crt")
	return os.WriteFile(filename, certBytes, 0644)
}

// GetCACertificate retrieves the CA's certificate from a file.
func (fs *FileStorage) GetCACertificate() ([]byte, error) {
	filename := filepath.Join(fs.dataDir, "ca", "ca.crt")
	return os.ReadFile(filename)
}

// SaveRevokedCertificate is a placeholder for file storage.
func (fs *FileStorage) SaveRevokedCertificate(serial string, revocationTime time.Time) error {
	// In a real implementation, you would save this to a file or database.
	return nil
}

// GetRevokedCertificates is a placeholder for file storage.
func (fs *FileStorage) GetRevokedCertificates() (map[string]time.Time, error) {
	// In a real implementation, you would load this from a file or database.
	return make(map[string]time.Time), nil
}
