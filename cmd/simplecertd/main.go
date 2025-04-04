package main

import (
	"fmt"
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

	// Initialize storage (for now, let's just log the config)
	store, err := storage.NewFileStorage(cfg.DataDir) // Example: File-based storage
	if err != nil {
		log.Fatalf("Failed to initialize storage: %v", err)
		os.Exit(1)
	}
	fmt.Printf("Storage initialized: %+v\n", store)

	// Initialize CA
	caService, err := ca.New(cfg, store)
	if err != nil {
		log.Fatalf("Failed to initialize CA service: %v", err)
		os.Exit(1)
	}
	fmt.Printf("CA service initialized: %+v\n", caService)

	// For now, let's just start a basic HTTP server (for potential API later)
	http.HandleFunc("/", func(w http.ResponseWriter, r *http.Request) {
		fmt.Fprintf(w, "Simple Cert CA is running!")
	})

	addr := ":8080"
	fmt.Printf("Listening on %s\n", addr)
	err = http.ListenAndServe(addr, nil)
	if err != nil {
		log.Fatalf("Error starting HTTP server: %v", err)
		os.Exit(1)
	}
}
