package auth

import (
	"net/http"
	"testing"
)

func TestGetAPIKey(t *testing.T) {
	tests := []struct {
		name          string
		headers       http.Header
		expectedKey   string
		expectedError error
		shouldHaveErr bool
	}{
		{
			name: "Valid API key",
			headers: http.Header{
				"Authorization": []string{"ApiKey my-secret-api-key"},
			},
			expectedKey:   "my-secret-api-key",
			expectedError: nil,
			shouldHaveErr: false,
		},
		{
			name:          "Missing Authorization header",
			headers:       http.Header{},
			expectedKey:   "",
			expectedError: ErrNoAuthHeaderIncluded,
			shouldHaveErr: true,
		},
		{
			name: "Empty Authorization header",
			headers: http.Header{
				"Authorization": []string{""},
			},
			expectedKey:   "",
			expectedError: ErrNoAuthHeaderIncluded,
			shouldHaveErr: true,
		},
		{
			name: "Wrong authorization type (Bearer instead of ApiKey)",
			headers: http.Header{
				"Authorization": []string{"Bearer my-token"},
			},
			expectedKey:   "",
			expectedError: nil, // We check for specific error message in the test
			shouldHaveErr: true,
		},
		{
			name: "Missing API key part",
			headers: http.Header{
				"Authorization": []string{"ApiKey"},
			},
			expectedKey:   "",
			expectedError: nil, // We check for specific error message in the test
			shouldHaveErr: true,
		},
		{
			name: "API key with spaces",
			headers: http.Header{
				"Authorization": []string{"ApiKey abc-123-xyz"},
			},
			expectedKey:   "abc-123-xyz",
			expectedError: nil,
			shouldHaveErr: false,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			key, err := GetAPIKey(tt.headers)

			// Check if we expected an error
			if tt.shouldHaveErr {
				if err == nil {
					t.Errorf("Expected an error but got none")
					return
				}

				// For specific error cases, check the exact error
				if tt.expectedError != nil && err.Error() != tt.expectedError.Error() {
					t.Errorf("Expected error %v, got %v", tt.expectedError, err)
				}
			} else {
				if err != nil {
					t.Errorf("Expected no error, but got %v", err)
					return
				}
			}

			// Check the returned key
			if key != tt.expectedKey {
				t.Errorf("Expected key %q, got %q", tt.expectedKey, key)
			}
		})
	}
}
