package main

import (
	"fmt"
	"io"
	"net/http"
	"os"

	"github.com/BitBloomLabs/simplecert/internal/auth"
	"github.com/BitBloomLabs/simplecert/internal/ca"
	"github.com/BitBloomLabs/simplecert/internal/config"
	"github.com/BitBloomLabs/simplecert/internal/storage"
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
	logger = l.With(zap.String("package", "main"))
}

func main() {
	cfg, err := config.LoadConfig()
	if err != nil {
		logger.Fatal("failed to load configuration", zap.Error(err))
		os.Exit(1)
	}
	logger.Info("Simple Cert CA starting...", zap.Any("configuration", cfg))

	// Initialize storage
	store, err := storage.NewStorage(
		cfg.StorageType,
		cfg.DataDir,
		cfg.DBHost,
		cfg.DBUser,
		cfg.DBPassword,
		cfg.DBName,
		cfg.DBPort,
		cfg.DBSSLMode,
		cfg.DBCert,
		cfg.DBKey,
		cfg.DBRootCert,
	)
	if err != nil {
		logger.Fatal("failed to initialize storage", zap.Error(err), zap.String("storage_type", cfg.StorageType))
		os.Exit(1)
	}
	logger.Info("storage initialized", zap.String("storage_type", cfg.StorageType))

	// Initialize CA
	caService, err := ca.New(cfg, store)
	if err != nil {
		logger.Fatal("failed to initialize CA service", zap.Error(err))
		os.Exit(1)
	}
	logger.Info("CA service initialized", zap.Bool("is_initialized", caService.IsInitialized()))

	// Register HTTP handlers
	http.HandleFunc("/", func(w http.ResponseWriter, r *http.Request) {
		fmt.Fprint(w, "Simple Cert CA is running!")
	})
	http.HandleFunc("/sign", handleSignRequest(caService, cfg))
	http.HandleFunc("/crl", handleGetCRL(caService, cfg))
	http.HandleFunc("/revoke", handleRevoke(caService, cfg))

	addr := ":8080"
	logger.Info("listening on address", zap.String("address", addr))
	err = http.ListenAndServe(addr, nil)
	if err != nil {
		logger.Fatal("error starting HTTP server", zap.Error(err), zap.String("address", addr))
		os.Exit(1)
	}
}

func handleSignRequest(caService *ca.Service, cfg *config.Config) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		// Authenticate and Authorize
		roles, err := auth.AuthenticateAPIKey(r, cfg)
		if err != nil {
			logger.Warn("authentication failed for /sign", zap.Error(err))
			http.Error(w, "Unauthorized", http.StatusUnauthorized)
			return
		}

		if err := auth.AuthorizeRequest("issuer", roles); err != nil {
			logger.Warn("authorization failed for /sign", zap.Error(err))
			http.Error(w, "Forbidden", http.StatusForbidden)
			return
		}

		if r.Method != http.MethodPost {
			logger.Warn("method not allowed for /sign", zap.String("method", r.Method))
			http.Error(w, "Method not allowed", http.StatusMethodNotAllowed)
			return
		}

		csrBytes, err := io.ReadAll(r.Body)
		if err != nil {
			logger.Error("failed to read request body for /sign", zap.Error(err))
			http.Error(w, fmt.Sprintf("Failed to read request body: %v", err), http.StatusBadRequest)
			return
		}
		defer r.Body.Close()

		signedCertPEM, err := caService.SignCertificate(csrBytes)
		if err != nil {
			logger.Error("failed to sign certificate", zap.Error(err))
			http.Error(w, fmt.Sprintf("Failed to sign certificate: %v", err), http.StatusInternalServerError)
			return
		}

		w.Header().Set("Content-Type", "application/x-pem-file")
		w.WriteHeader(http.StatusOK)
		_, err = w.Write(signedCertPEM)
		if err != nil {
			logger.Error("error writing response for /sign", zap.Error(err))
		}
		logger.Info("certificate signed successfully")
	}
}

func handleGetCRL(caService *ca.Service, cfg *config.Config) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		// Authenticate and Authorize (Example - You might not require auth for CRL)
		roles, err := auth.AuthenticateAPIKey(r, cfg)
		if err != nil {
			logger.Warn("authentication failed for /crl", zap.Error(err))
			http.Error(w, "Unauthorized", http.StatusUnauthorized)
			return
		}

		if err := auth.AuthorizeRequest("revoker", roles); err != nil {
			logger.Warn("authorization failed for /crl", zap.Error(err))
			http.Error(w, "Forbidden", http.StatusForbidden)
			return
		}

		if r.Method != http.MethodGet {
			logger.Warn("method not allowed for /crl", zap.String("method", r.Method))
			http.Error(w, "Method not allowed", http.StatusMethodNotAllowed)
			return
		}

		crlBytes, err := caService.GenerateCRL()
		if err != nil {
			logger.Error("failed to generate CRL", zap.Error(err))
			http.Error(w, fmt.Sprintf("Failed to generate CRL: %v", err), http.StatusInternalServerError)
			return
		}

		w.Header().Set("Content-Type", "application/pkix-crl")
		w.WriteHeader(http.StatusOK)
		_, err = w.Write(crlBytes)
		if err != nil {
			logger.Error("error writing response for /crl", zap.Error(err))
		}
		logger.Info("CRL generated and served successfully")
	}
}

func handleRevoke(caService *ca.Service, cfg *config.Config) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		// Authenticate and Authorize
		roles, err := auth.AuthenticateAPIKey(r, cfg)
		if err != nil {
			logger.Warn("authentication failed for /revoke", zap.Error(err))
			http.Error(w, "Unauthorized", http.StatusUnauthorized)
			return
		}

		if err := auth.AuthorizeRequest("revoker", roles); err != nil {
			logger.Warn("authorization failed for /revoke", zap.Error(err))
			http.Error(w, "Forbidden", http.StatusForbidden)
			return
		}

		if r.Method != http.MethodGet {
			logger.Warn("method not allowed for /revoke", zap.String("method", r.Method))
			http.Error(w, "Method not allowed", http.StatusMethodNotAllowed)
			return
		}

		serial := r.URL.Query().Get("serial")
		if serial == "" {
			logger.Warn("missing 'serial' parameter in /revoke request")
			http.Error(w, "Missing 'serial' parameter", http.StatusBadRequest)
			return
		}

		err = caService.RevokeCertificate(serial)
		if err != nil {
			logger.Error("failed to revoke certificate", zap.Error(err), zap.String("serial", serial))
			http.Error(w, fmt.Sprintf("Failed to revoke certificate: %v", err), http.StatusInternalServerError)
			return
		}

		fmt.Fprintf(w, "Certificate with serial '%s' revoked", serial)
		logger.Info("certificate revoked successfully", zap.String("serial", serial))
	}
}
