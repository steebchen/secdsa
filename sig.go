package main

import (
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/sha256"
	"crypto/x509"
	"encoding/base64"
	"encoding/pem"
	"fmt"
	"io"
	"log"
)

type Signature struct {
	curve elliptic.Curve // http://golang.org/pkg/crypto/elliptic/#P256
	key   *ecdsa.PrivateKey
}

type Option func(*Signature)

// New Signature instance. Use elliptic.P256 if unsure.
func New(curve elliptic.Curve, options ...Option) *Signature {
	sig := &Signature{
		curve: curve,
	}

	for _, option := range options {
		option(sig)
	}

	if sig.key == nil {
		panic("no key provided in signature.")
	}

	return sig
}

type Keys struct {
	key *ecdsa.PrivateKey
}

func WithGenerateKey() Option {
	return func(s *Signature) {
		key, err := ecdsa.GenerateKey(s.curve, rand.Reader)
		if err != nil {
			panic(err)
		}

		log.Printf("private key: %+v", key)
		log.Printf("public key: %+v", key.PublicKey)

		s.key = key
	}
}

func WithKey(key *ecdsa.PrivateKey) Option {
	return func(s *Signature) {
		s.key = key
	}
}

// ExportPrivateKey private key
func (s *Signature) ExportPrivateKey() (string, error) {
	encoded, err := x509.MarshalECPrivateKey(s.key)
	if err != nil {
		return "", err
	}

	pemEncoded := pem.EncodeToMemory(&pem.Block{Type: "EC PRIVATE KEY", Bytes: encoded})

	return string(pemEncoded), nil
}

// ExportPublicKey public key
func (s *Signature) ExportPublicKey() (string, error) {
	encoded, err := x509.MarshalPKIXPublicKey(&s.key.PublicKey)
	if err != nil {
		return "", err
	}

	log.Printf("encoded: %s", encoded)

	pemEncodedPub := pem.EncodeToMemory(&pem.Block{Type: "PUBLIC KEY", Bytes: encoded})

	log.Printf("pemEncodedPub: %s", pemEncodedPub)

	return string(pemEncodedPub), nil
}

// ImportPrivateKey private key
func ImportPrivateKey(pemKey string) (*ecdsa.PrivateKey, error) {
	block, _ := pem.Decode([]byte(pemKey))

	privateKey, err := x509.ParseECPrivateKey(block.Bytes)
	if err != nil {
		return nil, err
	}

	return privateKey, nil
}

// ImportPublicKey public key
func ImportPublicKey(pubKey string) (publicKey *ecdsa.PublicKey, err error) {
	blockPub, _ := pem.Decode([]byte(pubKey))

	x509EncodedPub := blockPub.Bytes

	genericPublicKey, err := x509.ParsePKIXPublicKey(x509EncodedPub)
	publicKey = genericPublicKey.(*ecdsa.PublicKey)

	return
}

func (s *Signature) Create(input string) ([]byte, error) {
	hash, err := s.createHash(input)
	if err != nil {
		return nil, err
	}

	sig, err := ecdsa.SignASN1(rand.Reader, s.key, hash)
	if err != nil {
		return nil, err
	}

	return sig, nil
}

func (s *Signature) Verify(input string, signature []byte) (bool, error) {
	hash, err := s.createHash(input)
	if err != nil {
		return false, err
	}
	return ecdsa.VerifyASN1(&s.key.PublicKey, hash, signature), nil
}

func (s *Signature) CreateBase64(input string) (string, error) {
	sig, err := s.Create(input)
	if err != nil {
		return "", err
	}

	return base64.StdEncoding.EncodeToString(sig), nil
}

func (s *Signature) VerifyBase64(input string, signature string) (bool, error) {
	sig, err := base64.StdEncoding.DecodeString(signature)
	if err != nil {
		return false, err
	}

	return s.Verify(input, sig)
}

func (s *Signature) createHash(input string) ([]byte, error) {
	h := sha256.New()

	_, err := io.WriteString(h, input)
	if err != nil {
		return nil, fmt.Errorf("could not create hash: %w", err)
	}

	return h.Sum(nil), nil
}
