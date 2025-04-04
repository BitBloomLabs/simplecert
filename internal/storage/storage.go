package storage

import (
	"os"
	"path/filepath"
)

// Storage is an interface for storing and retrieving CA data.
type Storage interface {
	SaveCertificate(serial string, certBytes []byte) error
	GetCertificate(serial string) ([]byte, error)
	SaveCRL(crlBytes []byte) error
	GetLatestCRL() ([]byte, error)
	// Add other storage methods as needed
}

// FileStorage is a basic file-based storage implementation.
type FileStorage struct {
	dataDir string
}

// NewFileStorage creates a new FileStorage instance.
func NewFileStorage(dataDir string) (*FileStorage, error) {
	err := os.MkdirAll(dataDir, 0755)
	if err != nil {
		return nil, err
	}
	return &FileStorage{dataDir: dataDir}, nil
}

// SaveCertificate saves a certificate to a file.
func (fs *FileStorage) SaveCertificate(serial string, certBytes []byte) error {
	filename := filepath.Join(fs.dataDir, "certs", serial+".crt")
	err := os.MkdirAll(filepath.Dir(filename), 0755)
	if err != nil {
		return err
	}
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
	err := os.MkdirAll(filepath.Dir(filename), 0755)
	if err != nil {
		return err
	}
	return os.WriteFile(filename, crlBytes, 0644)
}

// GetLatestCRL retrieves the latest CRL from a file.
func (fs *FileStorage) GetLatestCRL() ([]byte, error) {
	filename := filepath.Join(fs.dataDir, "crl", "crl.pem")
	return os.ReadFile(filename)
}
