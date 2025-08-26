package webhook

import (
	"crypto/hmac"
	"crypto/sha256"
	"encoding/hex"
	"testing"
)

func TestVerifySignature(t *testing.T) {
	tests := []struct {
		name      string
		payload   []byte
		signature string
		secret    string
		want      bool
	}{
		{
			name:      "valid signature",
			payload:   []byte(`{"test": "data"}`),
			signature: "sha256=",
			secret:    "mysecret",
			want:      true,
		},
		{
			name:      "invalid signature",
			payload:   []byte(`{"test": "data"}`),
			signature: "sha256=invalid",
			secret:    "mysecret",
			want:      false,
		},
		{
			name:      "missing sha256 prefix",
			payload:   []byte(`{"test": "data"}`),
			signature: "invalid",
			secret:    "mysecret",
			want:      false,
		},
		{
			name:      "empty secret rejects signature",
			payload:   []byte(`{"test": "data"}`),
			signature: "sha256=anything",
			secret:    "",
			want:      false,
		},
	}

	// Fix the first test with correct signature
	mac := hmac.New(sha256.New, []byte("mysecret"))
	mac.Write([]byte(`{"test": "data"}`))
	tests[0].signature = "sha256=" + hex.EncodeToString(mac.Sum(nil))

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			if got := VerifySignature(tt.payload, tt.signature, tt.secret); got != tt.want {
				t.Errorf("VerifySignature() = %v, want %v", got, tt.want)
			}
		})
	}
}
