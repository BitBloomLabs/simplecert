package auth

import (
	"fmt"
	"net/http"
	"strings"

	"github.com/BitBloomLabs/simplecert/internal/storage"
	"go.uber.org/zap"
)

var logger *zap.Logger

func init() {
	logger = zap.L().With(zap.String("package", "auth"))
}

// AuthenticateAPIKey authenticates the request using the API key from the headers and storage.
// It returns the roles associated with the API key if authentication is successful,
// or an error if authentication fails.
func AuthenticateAPIKey(r *http.Request, store storage.Storage) ([]string, error) {
	apiKey, err := GetAPIKeyFromHeader(r)
	if err != nil {
		return nil, fmt.Errorf("auth: %w", err)
	}

	roles, err := store.GetAPIKey(apiKey)
	if err != nil {
		return nil, fmt.Errorf("auth: failed to get API key from storage: %w", err)
	}

	if roles == nil {
		return nil, fmt.Errorf("auth: invalid API key")
	}

	return roles, nil
}

// AuthorizeRequest checks if the given roles are authorized to perform the requested action.
func AuthorizeRequest(requiredRole string, userRoles []string) error {
	for _, role := range userRoles {
		if role == requiredRole {
			return nil
		}
	}
	return fmt.Errorf("auth: unauthorized: missing role '%s'", requiredRole)
}

// GetAPIKeyFromHeader extracts the API key from the request header.
// For now, we'll just get it from "X-API-Key". You might want to support other headers.
func GetAPIKeyFromHeader(r *http.Request) (string, error) {
	apiKey := r.Header.Get("X-API-Key")
	if apiKey == "" {
		return "", fmt.Errorf("auth: missing API key")
	}
	return apiKey, nil
}

// ExtractBearerToken extracts a Bearer token from the Authorization header.
// This is an example and you might not need it for API keys.
func ExtractBearerToken(header string) (string, error) {
	parts := strings.Split(header, " ")
	if len(parts) != 2 || strings.ToLower(parts[0]) != "bearer" {
		return "", fmt.Errorf("auth: invalid Authorization header format")
	}
	return parts[1], nil
}
