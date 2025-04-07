package storage

import (
	"database/sql"
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"time"

	_ "github.com/lib/pq" // Import the PostgreSQL driver
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
	// Methods for revoked certificates
	SaveRevokedCertificate(serial string, revocationTime time.Time) error
	GetRevokedCertificates() (map[string]time.Time, error)
	// Add other storage methods as needed
}

// FileStorage is a basic file-based storage implementation.
type FileStorage struct {
	dataDir string
}

// PostgreSQLStorage is a PostgreSQL database storage implementation.
type PostgreSQLStorage struct {
	db         *sql.DB
	dbHost     string
	dbUser     string
	dbPassword string
	dbName     string
	dbPort     int
	dbSSLMode  string
	dbCert     string
	dbKey      string
	dbRootCert string
}

// NewStorage creates a new Storage instance based on the configuration.
func NewStorage(storageType string, dataDir string, dbHost string, dbUser string, dbPassword string, dbName string, dbPort int, dbSSLMode string, dbCert string, dbKey string, dbRootCert string) (Storage, error) {
	switch storageType {
	case "file":
		return NewFileStorage(dataDir)
	case "postgres":
		return NewPostgreSQLStorage(dbHost, dbUser, dbPassword, dbName, dbPort, dbSSLMode, dbCert, dbKey, dbRootCert)
	default:
		return nil, fmt.Errorf("invalid storage type: %s", storageType)
	}
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

// NewPostgreSQLStorage creates a new PostgreSQLStorage instance.
func NewPostgreSQLStorage(dbHost string, dbUser string, dbPassword string, dbName string, dbPort int, dbSSLMode string, dbCert string, dbKey string, dbRootCert string) (*PostgreSQLStorage, error) {
	connStr := fmt.Sprintf(
		"host=%s user=%s password=%s dbname=%s port=%d sslmode=%s",
		dbHost, dbUser, dbPassword, dbName, dbPort, dbSSLMode,
	)

	if dbCert != "" {
		connStr += " sslcert=" + dbCert
	}
	if dbKey != "" {
		connStr += " sslkey=" + dbKey
	}
	if dbRootCert != "" {
		connStr += " sslrootcert=" + dbRootCert
	}

	db, err := sql.Open("postgres", connStr)
	if err != nil {
		return nil, fmt.Errorf("failed to open PostgreSQL database: %w", err)
	}

	err = db.Ping()
	if err != nil {
		db.Close()
		return nil, fmt.Errorf("failed to connect to PostgreSQL database: %w", err)
	}

	// Create the revoked_certificates table if it doesn't exist
	_, err = db.Exec(`
		CREATE TABLE IF NOT EXISTS revoked_certificates (
			serial TEXT PRIMARY KEY,
			revocation_time TIMESTAMP WITH TIME ZONE NOT NULL
		);
	`)
	if err != nil {
		db.Close()
		return nil, fmt.Errorf("failed to create revoked_certificates table: %w", err)
	}

	// Create other tables if they don't exist and add unique constraints
	_, err = db.Exec(`
		CREATE TABLE IF NOT EXISTS certificates (
			serial TEXT PRIMARY KEY,
			certificate_data BYTEA NOT NULL
		);
	`)
	if err != nil {
		db.Close()
		return nil, fmt.Errorf("failed to create certificates table: %w", err)
	}

	_, err = db.Exec(`
		CREATE TABLE IF NOT EXISTS crls (
			crl_data BYTEA NOT NULL UNIQUE,
			created_at TIMESTAMP WITH TIME ZONE DEFAULT NOW()
		);
	`)
	if err != nil {
		db.Close()
		return nil, fmt.Errorf("failed to create crls table: %w", err)
	}

	_, err = db.Exec(`
		CREATE TABLE IF NOT EXISTS ca_data (
			key_data BYTEA UNIQUE,
			cert_data BYTEA UNIQUE
		);
	`)
	if err != nil {
		db.Close()
		return nil, fmt.Errorf("failed to create ca_data table: %w", err)
	}

	return &PostgreSQLStorage{
		db:         db,
		dbHost:     dbHost,
		dbUser:     dbUser,
		dbPassword: dbPassword,
		dbName:     dbName,
		dbPort:     dbPort,
		dbSSLMode:  dbSSLMode,
		dbCert:     dbCert,
		dbKey:      dbKey,
		dbRootCert: dbRootCert,
	}, nil
}

// SaveCertificate saves a certificate to the PostgreSQL database.
func (s *PostgreSQLStorage) SaveCertificate(serial string, certBytes []byte) error {
	_, err := s.db.Exec(
		"INSERT INTO certificates (serial, certificate_data) VALUES ($1, $2) ON CONFLICT (serial) DO UPDATE SET certificate_data = $2",
		serial, certBytes,
	)
	if err != nil {
		return fmt.Errorf("failed to save certificate: %w", err)
	}
	return nil
}

// GetCertificate retrieves a certificate from the PostgreSQL database.
func (s *PostgreSQLStorage) GetCertificate(serial string) ([]byte, error) {
	row := s.db.QueryRow("SELECT certificate_data FROM certificates WHERE serial = $1", serial)
	var certBytes []byte
	err := row.Scan(&certBytes)
	if err != nil {
		if errors.Is(err, sql.ErrNoRows) {
			return nil, nil // Certificate not found
		}
		return nil, fmt.Errorf("failed to get certificate: %w", err)
	}
	return certBytes, nil
}

// SaveCRL saves the CRL to the PostgreSQL database.
func (s *PostgreSQLStorage) SaveCRL(crlBytes []byte) error {
	_, err := s.db.Exec(
		"INSERT INTO crls (crl_data) VALUES ($1) ON CONFLICT (crl_data) DO UPDATE SET crl_data = $1",
		crlBytes,
	)
	if err != nil {
		return fmt.Errorf("failed to save CRL: %w", err)
	}
	return nil
}

// GetLatestCRL retrieves the latest CRL from the PostgreSQL database.
func (s *PostgreSQLStorage) GetLatestCRL() ([]byte, error) {
	row := s.db.QueryRow("SELECT crl_data FROM crls ORDER BY created_at DESC LIMIT 1") // Assuming you have a created_at column
	var crlBytes []byte
	err := row.Scan(&crlBytes)
	if err != nil {
		if errors.Is(err, sql.ErrNoRows) {
			return nil, nil // CRL not found
		}
		return nil, fmt.Errorf("failed to get latest CRL: %w", err)
	}
	return crlBytes, nil
}

// SaveCAPrivateKey saves the CA's private key to the PostgreSQL database.
func (s *PostgreSQLStorage) SaveCAPrivateKey(keyBytes []byte) error {
	_, err := s.db.Exec(
		"INSERT INTO ca_data (key_data) VALUES ($1) ON CONFLICT (key_data) DO UPDATE SET key_data = $1",
		keyBytes,
	)
	if err != nil {
		return fmt.Errorf("failed to save CA private key: %w", err)
	}
	return nil
}

// GetCAPrivateKey retrieves the CA's private key from the PostgreSQL database.
func (s *PostgreSQLStorage) GetCAPrivateKey() ([]byte, error) {
	row := s.db.QueryRow("SELECT key_data FROM ca_data LIMIT 1") // Assuming only one CA key
	var keyBytes []byte
	err := row.Scan(&keyBytes)
	if err != nil {
		if errors.Is(err, sql.ErrNoRows) {
			return nil, nil // CA key not found
		}
		return nil, fmt.Errorf("failed to get CA private key: %w", err)
	}
	return keyBytes, nil
}

// SaveCACertificate saves the CA's certificate to the PostgreSQL database.
func (s *PostgreSQLStorage) SaveCACertificate(certBytes []byte) error {
	_, err := s.db.Exec(
		"INSERT INTO ca_data (cert_data) VALUES ($1) ON CONFLICT (cert_data) DO UPDATE SET cert_data = $1",
		certBytes,
	)
	if err != nil {
		return fmt.Errorf("failed to save CA certificate: %w", err)
	}
	return nil
}

// GetCACertificate retrieves the CA's certificate from the PostgreSQL database.
func (s *PostgreSQLStorage) GetCACertificate() ([]byte, error) {
	row := s.db.QueryRow("SELECT cert_data FROM ca_data LIMIT 1") // Assuming only one CA cert
	var certBytes []byte
	err := row.Scan(&certBytes)
	if err != nil {
		if errors.Is(err, sql.ErrNoRows) {
			return nil, nil // CA certificate not found
		}
		return nil, fmt.Errorf("failed to get CA certificate: %w", err)
	}
	return certBytes, nil
}

// SaveRevokedCertificate saves a revoked certificate to the PostgreSQL database.
func (s *PostgreSQLStorage) SaveRevokedCertificate(serial string, revocationTime time.Time) error {
	_, err := s.db.Exec(
		"INSERT INTO revoked_certificates (serial, revocation_time) VALUES ($1, $2) ON CONFLICT (serial) DO UPDATE SET revocation_time = $2",
		serial, revocationTime,
	)
	if err != nil {
		return fmt.Errorf("failed to save revoked certificate: %w", err)
	}
	return nil
}

// GetRevokedCertificates retrieves all revoked certificates from the PostgreSQL database.
func (s *PostgreSQLStorage) GetRevokedCertificates() (map[string]time.Time, error) {
	rows, err := s.db.Query("SELECT serial, revocation_time FROM revoked_certificates")
	if err != nil {
		return nil, fmt.Errorf("failed to get revoked certificates: %w", err)
	}
	defer rows.Close()

	revokedCerts := make(map[string]time.Time)
	for rows.Next() {
		var serial string
		var revocationTime time.Time
		if err := rows.Scan(&serial, &revocationTime); err != nil {
			return nil, fmt.Errorf("failed to scan revoked certificate row: %w", err)
		}
		revokedCerts[serial] = revocationTime
	}
	if err := rows.Err(); err != nil {
		return nil, fmt.Errorf("error iterating revoked certificate rows: %w", err)
	}

	return revokedCerts, nil
}
