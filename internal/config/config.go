package config

import "os"

// Config holds the CA configuration.
type Config struct {
	DataDir string // Directory to store CA data (keys, certificates, CRLs)
	// Add other configuration options here later
}

// LoadConfig loads the CA configuration from environment variables or defaults.
func LoadConfig() (*Config, error) {
	cfg := &Config{
		DataDir: os.Getenv("SIMPLECERT_DATA_DIR"),
	}
	if cfg.DataDir == "" {
		cfg.DataDir = "./data" // Default data directory
	}
	// Add more configuration loading logic here later
	return cfg, nil
}
