package main

import (
	"fmt"
	"io"
	"log"
	"net/http"
	"os"

	"github.com/BitBloomLabs/simplecert/internal/ca"
	"github.com/BitBloomLabs/simplecert/internal/config"
	"github.com/BitBloomLabs/simplecert/internal/storage"
)

func main() {
	cfg, err := config.LoadConfig()
	if err != nil {
		log.Fatalf("Failed to load configuration: %v", err)
		os.Exit(1)
	}
	fmt.Println("Simple Cert CA starting...")
	fmt.Printf("Configuration: %+v\n", cfg)

	// Initialize storage
	store, err := storage.NewFileStorage(cfg.DataDir)
	if err != nil {
		log.Fatalf("Failed to initialize storage: %v", err)
		os.Exit(1)
	}
	fmt.Printf("Storage initialized in: %s\n", cfg.DataDir)

	// Initialize CA
	caService, err := ca.New(cfg, store)
	if err != nil {
		log.Fatalf("Failed to initialize CA service: %v", err)
		os.Exit(1)
	}
	fmt.Printf("CA service initialized. Is CA initialized? %t\n", caService.IsInitialized())

	// Register HTTP handlers
	http.HandleFunc("/", func(w http.ResponseWriter, r *http.Request) {
		fmt.Fprintf(w, "Simple Cert CA is running!")
	})
	http.HandleFunc("/sign", handleSignRequest(caService))
	http.HandleFunc("/crl", handleGetCRL(caService))

	// http.HandleFunc("/revoke", handleRevoke(caService))

	addr := ":8080"
	fmt.Printf("Listening on %s\n", addr)
	err = http.ListenAndServe(addr, nil)
	if err != nil {
		log.Fatalf("Error starting HTTP server: %v", err)
		os.Exit(1)
	}
}

// func handleRevoke(caService *ca.Service) http.HandlerFunc {
// 	return func(w http.ResponseWriter, r *http.Request) {
// 		serial := r.URL.Query().Get("serial")
// 		if serial == "" {
// 			http.Error(w, "Missing 'serial' parameter", http.StatusBadRequest)
// 			return
// 		}
// 		err := caService.RevokeCertificate(serial)
// 		if err != nil {
// 			http.Error(w, fmt.Sprintf("Failed to revoke certificate: %v", err), http.StatusInternalServerError)
// 			return
// 		}
// 		fmt.Fprintf(w, "Certificate with serial '%s' revoked", serial)
// 	}
// }

func handleSignRequest(caService *ca.Service) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		if r.Method != http.MethodPost {
			http.Error(w, "Method not allowed", http.StatusMethodNotAllowed)
			return
		}

		csrBytes, err := io.ReadAll(r.Body)
		if err != nil {
			http.Error(w, fmt.Sprintf("Failed to read request body: %v", err), http.StatusBadRequest)
			return
		}
		defer r.Body.Close()

		signedCertPEM, err := caService.SignCertificate(csrBytes)
		if err != nil {
			log.Printf("Error signing certificate: %v", err)
			http.Error(w, fmt.Sprintf("Failed to sign certificate: %v", err), http.StatusInternalServerError)
			return
		}

		w.Header().Set("Content-Type", "application/x-pem-file")
		w.WriteHeader(http.StatusOK)
		_, err = w.Write(signedCertPEM)
		if err != nil {
			log.Printf("Error writing response: %v", err)
		}
	}
}

func handleGetCRL(caService *ca.Service) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		if r.Method != http.MethodGet {
			http.Error(w, "Method not allowed", http.StatusMethodNotAllowed)
			return
		}

		crlBytes, err := caService.GenerateCRL()
		if err != nil {
			log.Printf("Error generating CRL: %v", err)
			http.Error(w, fmt.Sprintf("Failed to generate CRL: %v", err), http.StatusInternalServerError)
			return
		}

		w.Header().Set("Content-Type", "application/pkix-crl")
		w.WriteHeader(http.StatusOK)
		_, err = w.Write(crlBytes)
		if err != nil {
			log.Printf("Error writing CRL response: %v", err)
		}
	}
}
