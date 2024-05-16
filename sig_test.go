package main

import (
	"crypto/elliptic"
	"log"
	"testing"

	"github.com/stretchr/testify/assert"
)

func TestSignature(t *testing.T) {
	tests := []struct {
		name string
		run  func(t *testing.T, s *Signature)
	}{{
		name: "test create and verify",
		run: func(t *testing.T, s *Signature) {
			input := "This is a message to be signed and verified by ECDSA!"

			sig, err := s.Create(input)
			assert.NoError(t, err)

			got, err := s.Verify(input, sig)
			assert.NoError(t, err)

			assert.Equalf(t, true, got, "Verify()")

			log.Printf("sig: %s", string(sig))
			log.Printf("input: %s", input)
			x, err := s.ExportPrivateKey()
			assert.NoError(t, err)
			log.Printf("exported private key: %s", x)
			y, err := s.ExportPublicKey()
			assert.NoError(t, err)
			log.Printf("exported public key: %s", y)
		},
	}, {
		name: "test create and verify base64",
		run: func(t *testing.T, s *Signature) {
			input := "This is a message to be signed and verified by ECDSA!"

			sig, err := s.CreateBase64(input)
			assert.NoError(t, err)

			got, err := s.VerifyBase64(input, sig)
			assert.NoError(t, err)

			assert.Equalf(t, true, got, "Verify()")
		},
	}}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			s := New(elliptic.P256(), WithGenerateKey())
			tt.run(t, s)
		})
	}
}

func TestImportExport(t *testing.T) {
	tests := []struct {
		name string
		run  func(t *testing.T)
	}{{
		name: "import and export keys",
		run: func(t *testing.T) {
			wantPublic := `-----BEGIN PUBLIC KEY-----
MFkwEwYHKoZIzj0CAQYIKoZIzj0DAQcDQgAECYMZJNlWzBVNj3lcTn8DXdSrU+Uy
k2FfPLdO+pAxFNKKcrSKaHE6/rDf7w06gVpgCQKkulthk2TdwmowL8puzw==
-----END PUBLIC KEY-----`

			wantPrivate := `-----BEGIN PUBLIC KEY-----
MFkwEwYHKoZIzj0CAQYIKoZIzj0DAQcDQgAECYMZJNlWzBVNj3lcTn8DXdSrU+Uy
k2FfPLdO+pAxFNKKcrSKaHE6/rDf7w06gVpgCQKkulthk2TdwmowL8puzw==
-----END PUBLIC KEY-----`

			key, err := ImportPrivateKey(wantPrivate)
			assert.NoError(t, err)

			s := New(elliptic.P256(), WithKey(key))

			exportPrivate, err := s.ExportPrivateKey()
			assert.NoError(t, err)

			exportPublic, err := s.ExportPublicKey()
			assert.NoError(t, err)

			assert.Equal(t, exportPrivate, wantPrivate)
			assert.Equal(t, exportPublic, wantPublic)
		},
	}, {
		name: "import",
		run: func(t *testing.T) {
			t.Skip("not implemented")

			// ImportPublicKey
			// ImportPrivateKey
		}}}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			tt.run(t)
		})
	}
}
