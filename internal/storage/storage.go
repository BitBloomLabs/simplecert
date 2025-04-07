package storage

import (
	"context"
	"database/sql"
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"time"

	_ "github.com/lib/pq" // Import the PostgreSQL driver
	"go.uber.org/zap"
	"go.uber.org/zap/zapcore"
)

var logger *zap.Logger

func init() {
	cfg := zap.NewDevelopmentConfig()
	cfg.EncoderConfig.EncodeTime = zapcore.ISO8601TimeEncoder
	l, err := cfg.Build()
	if err != nil {
		panic(err)
	}
	logger = l.With(zap.String("package", "storage"))
}

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
		return nil, fmt.Errorf("storage: invalid storage type: %s", storageType)
	}
}

// NewFileStorage creates a new FileStorage instance.
func NewFileStorage(dataDir string) (*FileStorage, error) {
	err := os.MkdirAll(filepath.Join(dataDir, "certs"), 0755)
	if err != nil {
		return nil, fmt.Errorf("storage: failed to create certs directory: %w", err)
	}
	err = os.MkdirAll(filepath.Join(dataDir, "crl"), 0755)
	if err != nil {
		return nil, fmt.Errorf("storage: failed to create crl directory: %w", err)
	}
	err = os.MkdirAll(filepath.Join(dataDir, "ca"), 0755)
	if err != nil {
		return nil, fmt.Errorf("storage: failed to create ca directory: %w", err)
	}
	return &FileStorage{dataDir: dataDir}, nil
}

// SaveCertificate saves a certificate to a file.
func (fs *FileStorage) SaveCertificate(serial string, certBytes []byte) error {
	filename := filepath.Join(fs.dataDir, "certs", serial+".crt")
	err := os.WriteFile(filename, certBytes, 0644)
	if err != nil {
		return fmt.Errorf("storage: failed to save certificate to file: %w", err)
	}
	logger.Info("certificate saved to file", zap.String("serial", serial), zap.String("filename", filename))
	return nil
}

// GetCertificate retrieves a certificate from a file.
func (fs *FileStorage) GetCertificate(serial string) ([]byte, error) {
	filename := filepath.Join(fs.dataDir, "certs", serial+".crt")
	certBytes, err := os.ReadFile(filename)
	if err != nil {
		return nil, fmt.Errorf("storage: failed to read certificate from file: %w", err)
	}
	logger.Info("certificate read from file", zap.String("serial", serial), zap.String("filename", filename))
	return certBytes, nil
}

// SaveCRL saves the CRL to a file.
func (fs *FileStorage) SaveCRL(crlBytes []byte) error {
	filename := filepath.Join(fs.dataDir, "crl", "crl.pem")
	err := os.WriteFile(filename, crlBytes, 0644)
	if err != nil {
		return fmt.Errorf("storage: failed to save CRL to file: %w", err)
	}
	logger.Info("CRL saved to file", zap.String("filename", filename))
	return nil
}

// GetLatestCRL retrieves the latest CRL from a file.
func (fs *FileStorage) GetLatestCRL() ([]byte, error) {
	filename := filepath.Join(fs.dataDir, "crl", "crl.pem")
	crlBytes, err := os.ReadFile(filename)
	if err != nil {
		return nil, fmt.Errorf("storage: failed to read CRL from file: %w", err)
	}
	logger.Info("CRL read from file", zap.String("filename", filename))
	return crlBytes, nil
}

// SaveCAPrivateKey saves the CA's private key to a file.
func (fs *FileStorage) SaveCAPrivateKey(keyBytes []byte) error {
	filename := filepath.Join(fs.dataDir, "ca", "ca.key")
	err := os.WriteFile(filename, keyBytes, 0600) // Sensitive data, restrict permissions
	if err != nil {
		return fmt.Errorf("storage: failed to save CA private key to file: %w", err)
	}
	logger.Info("CA private key saved to file", zap.String("filename", filename))
	return nil
}

// GetCAPrivateKey retrieves the CA's private key from a file.
func (fs *FileStorage) GetCAPrivateKey() ([]byte, error) {
	filename := filepath.Join(fs.dataDir, "ca", "ca.key")
	keyBytes, err := os.ReadFile(filename)
	if err != nil {
		return nil, fmt.Errorf("storage: failed to read CA private key from file: %w", err)
	}
	logger.Info("CA private key read from file", zap.String("filename", filename))
	return keyBytes, nil
}

// SaveCACertificate saves the CA's certificate to a file.
func (fs *FileStorage) SaveCACertificate(certBytes []byte) error {
	filename := filepath.Join(fs.dataDir, "ca", "ca.crt")
	err := os.WriteFile(filename, certBytes, 0644)
	if err != nil {
		return fmt.Errorf("storage: failed to save CA certificate to file: %w", err)
	}
	logger.Info("CA certificate saved to file", zap.String("filename", filename))
	return nil
}

// GetCACertificate retrieves the CA's certificate from a file.
func (fs *FileStorage) GetCACertificate() ([]byte, error) {
	filename := filepath.Join(fs.dataDir, "ca", "ca.crt")
	certBytes, err := os.ReadFile(filename)
	if err != nil {
		return nil, fmt.Errorf("storage: failed to read CA certificate from file: %w", err)
	}
	logger.Info("CA certificate read from file", zap.String("filename", filename))
	return certBytes, nil
}

// SaveRevokedCertificate is a placeholder for file storage.
func (fs *FileStorage) SaveRevokedCertificate(serial string, revocationTime time.Time) error {
	// In a real implementation, you would save this to a file or database.
	logger.Warn("SaveRevokedCertificate is a placeholder for file storage. Revocations are not persisted.", zap.String("serial", serial))
	return nil
}

// GetRevokedCertificates is a placeholder for file storage.
func (fs *FileStorage) GetRevokedCertificates() (map[string]time.Time, error) {
	// In a real implementation, you would load this from a file or database.
	logger.Warn("GetRevokedCertificates is a placeholder for file storage. Revocations are not persisted.")
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
		return nil, fmt.Errorf("storage: failed to open PostgreSQL database: %w", err)
	}

	err = db.PingContext(context.Background()) // Use PingContext
	if err != nil {
		db.Close()
		return nil, fmt.Errorf("storage: failed to connect to PostgreSQL database: %w", err)
	}

	// Create the revoked_certificates table if it doesn't exist
	_, err = db.ExecContext(context.Background(), `
		CREATE TABLE IF NOT EXISTS revoked_certificates (
			serial TEXT PRIMARY KEY,
			revocation_time TIMESTAMP WITH TIME ZONE NOT NULL
		);
	`)
	if err != nil {
		db.Close()
		return nil, fmt.Errorf("storage: failed to create revoked_certificates table: %w", err)
	}

	// Create other tables if they don't exist and add unique constraints
	_, err = db.ExecContext(context.Background(), `
		CREATE TABLE IF NOT EXISTS certificates (
			serial TEXT PRIMARY KEY,
			certificate_data BYTEA NOT NULL
		);
	`)
	if err != nil {
		db.Close()
		return nil, fmt.Errorf("storage: failed to create certificates table: %w", err)
	}

	_, err = db.ExecContext(context.Background(), `
		CREATE TABLE IF NOT EXISTS crls (
			crl_data BYTEA NOT NULL UNIQUE,
			created_at TIMESTAMP WITH TIME ZONE DEFAULT NOW()
		);
	`)
	if err != nil {
		db.Close()
		return nil, fmt.Errorf("storage: failed to create crls table: %w", err)
	}

	_, err = db.ExecContext(context.Background(), `
		CREATE TABLE IF NOT EXISTS ca_data (
			key_data BYTEA UNIQUE,
			cert_data BYTEA UNIQUE
		);
	`)
	if err != nil {
		db.Close()
		return nil, fmt.Errorf("storage: failed to create ca_data table: %w", err)
	}

	s := &PostgreSQLStorage{
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
	}
	logger.Info("PostgreSQLStorage initialized", zap.String("host", dbHost), zap.String("user", dbUser), zap.String("dbname", dbName), zap.Int("port", dbPort))
	return s, nil
}

// SaveCertificate saves a certificate to the PostgreSQL database.
func (s *PostgreSQLStorage) SaveCertificate(serial string, certBytes []byte) error {
	_, err := s.db.ExecContext(context.Background(),
		"INSERT INTO certificates (serial, certificate_data) VALUES ($1, $2) ON CONFLICT (serial) DO UPDATE SET certificate_data = $2",
		serial, certBytes,
	)
	if err != nil {
		return fmt.Errorf("storage: failed to save certificate: %w", err)
	}
	logger.Info("certificate saved to database", zap.String("serial", serial))
	return nil
}

// GetCertificate retrieves a certificate from the PostgreSQL database.
func (s *PostgreSQLStorage) GetCertificate(serial string) ([]byte, error) {
	row := s.db.QueryRowContext(context.Background(), "SELECT certificate_data FROM certificates WHERE serial = $1", serial)
	var certBytes []byte
	err := row.Scan(&certBytes)
	if err != nil {
		if errors.Is(err, sql.ErrNoRows) {
			logger.Info("certificate not found in database", zap.String("serial", serial))
			return nil, nil // Certificate not found
		}
		return nil, fmt.Errorf("storage: failed to get certificate: %w", err)
	}
	logger.Info("certificate retrieved from database", zap.String("serial", serial))
	return certBytes, nil
}

// SaveCRL saves the CRL to the PostgreSQL database.
func (s *PostgreSQLStorage) SaveCRL(crlBytes []byte) error {
	_, err := s.db.ExecContext(context.Background(),
		"INSERT INTO crls (crl_data) VALUES ($1) ON CONFLICT (crl_data) DO UPDATE SET crl_data = $1",
		crlBytes,
	)
	if err != nil {
		return fmt.Errorf("storage: failed to save CRL: %w", err)
	}
	logger.Info("CRL saved to database")
	return nil
}

// GetLatestCRL retrieves the latest CRL from the PostgreSQL database.
func (s *PostgreSQLStorage) GetLatestCRL() ([]byte, error) {
	row := s.db.QueryRowContext(context.Background(), "SELECT crl_data FROM crls ORDER BY created_at DESC LIMIT 1") // Assuming you have a created_at column
	var crlBytes []byte
	err := row.Scan(&crlBytes)
	if err != nil {
		if errors.Is(err, sql.ErrNoRows) {
			logger.Info("CRL not found in database")
			return nil, nil // CRL not found
		}
		return nil, fmt.Errorf("storage: failed to get latest CRL: %w", err)
	}
	logger.Info("latest CRL retrieved from database")
	return crlBytes, nil
}

// SaveCAPrivateKey saves the CA's private key to the PostgreSQL database.
func (s *PostgreSQLStorage) SaveCAPrivateKey(keyBytes []byte) error {
	_, err := s.db.ExecContext(context.Background(),
		"INSERT INTO ca_data (key_data) VALUES ($1) ON CONFLICT (key_data) DO UPDATE SET key_data = $1",
		keyBytes,
	)
	if err != nil {
		return fmt.Errorf("storage: failed to save CA private key: %w", err)
	}
	logger.Info("CA private key saved to database")
	return nil
}

// GetCAPrivateKey retrieves the CA's private key from the PostgreSQL database.
func (s *PostgreSQLStorage) GetCAPrivateKey() ([]byte, error) {
	row := s.db.QueryRowContext(context.Background(), "SELECT key_data FROM ca_data LIMIT 1") // Assuming only one CA key
	var keyBytes []byte
	err := row.Scan(&keyBytes)
	if err != nil {
		if errors.Is(err, sql.ErrNoRows) {
			logger.Info("CA private key not found in database")
			return nil, nil // CA key not found
		}
		return nil, fmt.Errorf("storage: failed to get CA private key: %w", err)
	}
	logger.Info("CA private key retrieved from database")
	return keyBytes, nil
}

// SaveCACertificate saves the CA's certificate to the PostgreSQL database.
func (s *PostgreSQLStorage) SaveCACertificate(certBytes []byte) error {
	_, err := s.db.ExecContext(context.Background(),
		"INSERT INTO ca_data (cert_data) VALUES ($1) ON CONFLICT (cert_data) DO UPDATE SET cert_data = $1",
		certBytes,
	)
	if err != nil {
		return fmt.Errorf("storage: failed to save CA certificate: %w", err)
	}
	logger.Info("CA certificate saved to database")
	return nil
}

// GetCACertificate retrieves the CA's certificate from the PostgreSQL database.
func (s *PostgreSQLStorage) GetCACertificate() ([]byte, error) {
	row := s.db.QueryRowContext(context.Background(), "SELECT cert_data FROM ca_data LIMIT 1") // Assuming only one CA cert
	var certBytes []byte
	err := row.Scan(&certBytes)
	if err != nil {
		if errors.Is(err, sql.ErrNoRows) {
			logger.Info("CA certificate not found in database")
			return nil, nil // CA certificate not found
		}
		return nil, fmt.Errorf("storage: failed to get CA certificate: %w", err)
	}
	logger.Info("CA certificate retrieved from database")
	return certBytes, nil
}

// SaveRevokedCertificate saves a revoked certificate to the PostgreSQL database.
func (s *PostgreSQLStorage) SaveRevokedCertificate(serial string, revocationTime time.Time) error {
	_, err := s.db.ExecContext(context.Background(),
		"INSERT INTO revoked_certificates (serial, revocation_time) VALUES ($1, $2) ON CONFLICT (serial) DO UPDATE SET revocation_time = $2",
		serial, revocationTime,
	)
	if err != nil {
		return fmt.Errorf("storage: failed to save revoked certificate: %w", err)
	}
	logger.Info("revoked certificate saved to database", zap.String("serial", serial))
	return nil
}

// GetRevokedCertificates retrieves all revoked certificates from the PostgreSQL database.
func (s *PostgreSQLStorage) GetRevokedCertificates() (map[string]time.Time, error) {
	rows, err := s.db.QueryContext(context.Background(), "SELECT serial, revocation_time FROM revoked_certificates")
	if err != nil {
		return nil, fmt.Errorf("storage: failed to get revoked certificates: %w", err)
	}
	defer rows.Close()

	revokedCerts := make(map[string]time.Time)
	for rows.Next() {
		var serial string
		var revocationTime time.Time
		if err := rows.Scan(&serial, &revocationTime); err != nil {
			return nil, fmt.Errorf("storage: failed to scan revoked certificate row: %w", err)
		}
		revokedCerts[serial] = revocationTime
	}
	if err := rows.Err(); err != nil {
		return nil, fmt.Errorf("storage: error iterating revoked certificate rows: %w", err)
	}

	logger.Info("revoked certificates retrieved from database", zap.Int("count", len(revokedCerts)))
	return revokedCerts, nil
}
