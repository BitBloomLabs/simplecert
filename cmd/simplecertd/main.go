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
	"github.com/labstack/echo/v4"
	"github.com/labstack/echo/v4/middleware"
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

	// Load users and API keys from the database (or use defaults if empty)
	if cfg.StorageType == "postgres" {
		for apiKey, apiKeyConfig := range cfg.APIKeys {
			err := store.SaveAPIKey(apiKey, apiKeyConfig.Roles)
			if err != nil {
				logger.Warn("failed to save API key to database, using in-memory data", zap.Error(err), zap.String("api_key", apiKey))
			} else {
				logger.Info("API key saved to database", zap.String("api_key", apiKey))
			}
		}
	} else {
		// logger.Info("using in-memory API keys", zap.String("storage_type", cfg.StorageType))
		logger.Error("in-memory storage not implemented", zap.String("storage_type", cfg.StorageType))
		os.Exit(1)
	}

	// Ensure HTTPS certificates
	certFile, keyFile, err := ca.EnsureHTTPSCertificates(cfg)
	if err != nil {
		logger.Fatal("failed to ensure HTTPS certificates", zap.Error(err))
		os.Exit(1)
	}

	e := echo.New()
	e.HideBanner = true
	e.Use(middleware.Recover())

	// Middle to pass caService, cfg, and store to handlers
	e.Use(func(next echo.HandlerFunc) echo.HandlerFunc {
		return func(c echo.Context) error {
			c.Set("caService", caService)
			c.Set("cfg", cfg)
			c.Set("store", store)
			return next(c)
		}
	})

	e.GET("/", func(c echo.Context) error {
		return c.String(http.StatusOK, "Simple Cert CA is running!")
	})
	e.POST("/sign", handleSignRequest)
	e.GET("/crl", handleGetCRL)
	e.POST("/revoke", handleRevoke)
	e.GET("/users", handleUsers)
	e.GET("/users/:username", handleUser)
	e.PUT("/users/:username", handleUser)
	e.DELETE("/users/:username", handleUser)

	address := cfg.HTTPSAddress
	logger.Info("listening on address", zap.String("address", address))
	err = e.StartTLS(address, certFile, keyFile)
	if err != nil {
		logger.Fatal("error starting HTTPS server", zap.Error(err), zap.String("address", address))
		os.Exit(1)
	}
}

func handleSignRequest(c echo.Context) error {
	caService := c.Get("caService").(*ca.Service)
	// cfg := c.Get("cfg").(*config.Config)
	store := c.Get("store").(storage.Storage)

	apiKey, err := auth.GetAPIKeyFromHeader(c.Request())
	if err != nil {
		logger.Warn("missing API key", zap.Error(err))
		return c.JSON(http.StatusUnauthorized, "Unauthorized")
	}

	roles, err := store.GetAPIKey(apiKey)
	if err != nil {
		logger.Error("failed to get API key from storage", zap.Error(err), zap.String("api_key", apiKey))
		return c.JSON(http.StatusUnauthorized, "Unauthorized")
	}
	if roles == nil {
		logger.Warn("invalid API key", zap.String("api_key", apiKey))
		return c.JSON(http.StatusUnauthorized, "Unauthorized")
	}

	if err := auth.AuthorizeRequest("issuer", roles); err != nil {
		logger.Warn("authorization failed for /sign", zap.Error(err), zap.Strings("roles", roles))
		return c.JSON(http.StatusForbidden, "Forbidden")
	}

	csrBytes, err := io.ReadAll(c.Request().Body)
	if err != nil {
		logger.Error("failed to read request body for /sign", zap.Error(err))
		return c.JSON(http.StatusBadRequest, fmt.Sprintf("Failed to read request body: %v", err))
	}
	defer c.Request().Body.Close()

	signedCertPEM, err := caService.SignCertificate(csrBytes)
	if err != nil {
		logger.Error("failed to sign certificate", zap.Error(err))
		return c.JSON(http.StatusInternalServerError, fmt.Sprintf("Failed to sign certificate: %v", err))
	}

	c.Response().Header().Set(echo.HeaderContentType, "application/x-pem-file")
	c.Response().WriteHeader(http.StatusOK)
	_, err = c.Response().Write(signedCertPEM)
	if err != nil {
		logger.Error("error writing response for /sign", zap.Error(err))
	}
	logger.Info("certificate signed successfully")

	return nil

}

func handleGetCRL(c echo.Context) error {
	caService := c.Get("caService").(*ca.Service)
	// cfg := c.Get("cfg").(*config.Config)
	store := c.Get("store").(storage.Storage)

	apiKey, err := auth.GetAPIKeyFromHeader(c.Request())
	if err != nil {
		logger.Warn("missing API key", zap.Error(err))
		return c.JSON(http.StatusUnauthorized, "Unauthorized")
	}

	roles, err := store.GetAPIKey(apiKey)
	if err != nil {
		logger.Error("failed to get API key from storage", zap.Error(err), zap.String("api_key", apiKey))
		return c.JSON(http.StatusUnauthorized, "Unauthorized")
	}
	if roles == nil {
		logger.Warn("invalid API key", zap.String("api_key", apiKey))
		return c.JSON(http.StatusUnauthorized, "Unauthorized")
	}

	if err := auth.AuthorizeRequest("revoker", roles); err != nil {
		logger.Warn("authorization failed for /crl", zap.Error(err), zap.Strings("roles", roles))
		return c.JSON(http.StatusForbidden, "Forbidden")
	}

	crlBytes, err := caService.GenerateCRL()
	if err != nil {
		logger.Error("failed to generate CRL", zap.Error(err))
		return c.JSON(http.StatusInternalServerError, fmt.Sprintf("Failed to generate CRL: %v", err))
	}

	c.Response().Header().Set(echo.HeaderContentType, "application/pkix-crl")
	c.Response().WriteHeader(http.StatusOK)
	_, err = c.Response().Write(crlBytes)
	if err != nil {
		logger.Error("error writing response for /crl", zap.Error(err))
	}
	logger.Info("CRL generated and served successfully")

	return nil
}

func handleRevoke(c echo.Context) error {
	caService := c.Get("caService").(*ca.Service)
	// cfg := c.Get("cfg").(*config.Config)
	store := c.Get("store").(storage.Storage)

	apiKey, err := auth.GetAPIKeyFromHeader(c.Request())
	if err != nil {
		logger.Warn("missing API key", zap.Error(err))
		return c.JSON(http.StatusUnauthorized, "Unauthorized")
	}

	roles, err := store.GetAPIKey(apiKey)
	if err != nil {
		logger.Error("failed to get API key from storage", zap.Error(err), zap.String("api_key", apiKey))
		return c.JSON(http.StatusUnauthorized, "Unauthorized")
	}
	if roles == nil {
		logger.Warn("invalid API key", zap.String("api_key", apiKey))
		return c.JSON(http.StatusUnauthorized, "Unauthorized")
	}

	if err := auth.AuthorizeRequest("revoker", roles); err != nil {
		logger.Warn("authorization failed for /revoke", zap.Error(err), zap.Strings("roles", roles))
		return c.JSON(http.StatusForbidden, "Forbidden")
	}

	if c.Request().Method != http.MethodGet {
		logger.Warn("method not allowed for /revoke", zap.String("method", c.Request().Method))
		return c.JSON(http.StatusMethodNotAllowed, "Method not allowed")
	}

	serial := c.QueryParam("serial")
	if serial == "" {
		logger.Warn("missing 'serial' parameter in /revoke request")
		return c.JSON(http.StatusBadRequest, "Missing 'serial' parameter")
	}

	err = caService.RevokeCertificate(serial)
	if err != nil {
		logger.Error("failed to revoke certificate", zap.Error(err), zap.String("serial", serial))
		return c.JSON(http.StatusInternalServerError, fmt.Sprintf("Failed to revoke certificate: %v", err))
	}

	fmt.Fprintf(c.Response(), "Certificate with serial '%s' revoked", serial)
	logger.Info("certificate revoked successfully")

	return nil
}

// handleUsers handles user management operations on the /users endpoint.
func handleUsers(c echo.Context) error {
	// store := c.Get("store").(storage.Storage)
	switch c.Request().Method {
	case http.MethodGet:
		listUsers(c)
	case http.MethodPost:
		createUser(c)
	default:
		logger.Warn("method not allowed for /users", zap.String("method", c.Request().Method))
		return c.JSON(http.StatusMethodNotAllowed, "Method not allowed")
	}

	return nil
}

// handleUser handles user management operations on the /users/{username} endpoint.
func handleUser(c echo.Context) error {
	// store := c.Get("store").(storage.Storage)
	username := c.Param("username")
	if username == "" {
		logger.Warn("missing username in /users/ request")
		return c.JSON(http.StatusBadRequest, "Missing username")
	}

	switch c.Request().Method {
	case http.MethodGet:
		// getUser(c, store, username) // Implement if you need to get a single user
	case http.MethodPut:
		updateUser(c, username)
	case http.MethodDelete:
		deleteUser(c, username)
	default:
		logger.Warn("method not allowed for /users/{username}", zap.String("method", c.Request().Method))
		return c.JSON(http.StatusMethodNotAllowed, "Method not allowed")
	}
	return nil
}

// createUser handles the creation of a new user.
func createUser(c echo.Context) error {
	// store := c.Get("store").(storage.Storage)
	// Implement your logic to create a user here.
	// You'll need to parse the request body to get the user details.
	// Example:
	//   var user User
	//   if err := json.NewDecoder(r.Body).Decode(&user); err != nil { ... }
	//   if err := store.AddUser(user.Username, user.Password, user.Roles); err != nil { ... }
	logger.Info("createUser endpoint called")
	return c.JSON(http.StatusNotImplemented, "Not Implemented")
}

// updateUser handles the updating of an existing user.
func updateUser(c echo.Context, username string) error {
	// store := c.Get("store").(storage.Storage)
	// Implement your logic to update a user here.
	// You'll need to parse the request body to get the updated user details.
	// Example:
	//   var user User
	//   if err := json.NewDecoder(r.Body).Decode(&user); err != nil { ... }
	//   if err := store.UpdateUser(username, user.Password, user.Roles); err != nil { ... }
	logger.Info("updateUser endpoint called", zap.String("username", username))
	return c.JSON(http.StatusNotImplemented, "Not Implemented")
}

// deleteUser handles the deletion of a user.
func deleteUser(c echo.Context, username string) error {
	// store := c.Get("store").(storage.Storage)
	// Implement your logic to delete a user here.
	// Example:
	//   if err := store.DeleteUser(username); err != nil { ... }
	logger.Info("deleteUser endpoint called", zap.String("username", username))
	return c.JSON(http.StatusNotImplemented, "Not Implemented")
}

// listUsers handles the listing of all users.
func listUsers(c echo.Context) error {
	// store := c.Get("store").(storage.Storage)
	// Implement your logic to list all users here.
	// Example:
	//   users, err := store.ListUsers()
	//   if err != nil { ... }
	//   json.NewEncoder(w).Encode(users)
	logger.Info("listUsers endpoint called")
	return c.JSON(http.StatusNotImplemented, "Not Implemented")
}
