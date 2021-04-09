package main

import (
	"crypto"
	"crypto/aes"
	"crypto/cipher"
	"crypto/rand"
	"crypto/rsa"
	"crypto/x509"
	"encoding/pem"
	"errors"
	"fmt"
	"io"
	"io/ioutil"
)

type RSASigner struct {
	privateKey *rsa.PrivateKey
}

func NewRSASigner(privateKeyPath string) (*RSASigner, error) {
	key, err := loadRSAPrivateKey(privateKeyPath)
	if err != nil {
		return nil, err
	}
	signer := RSASigner{key}
	return &signer, nil
}

func (signer RSASigner) SignSHA256Digest(data [32]byte) (*[256]byte, error) {
	sig, err := rsa.SignPKCS1v15(rand.Reader, signer.privateKey, crypto.SHA256, data[:])
	if err != nil {
		return nil, err
	}
	var cpy [256]byte
	copy(cpy[:], sig)
	return &cpy, nil
}

// Based on: https://gist.github.com/raztud/0e9b3d15a32ec6a5840e446c8e81e308
func parseRSAPrivateKey(pemBytes []byte) (*rsa.PrivateKey, error) {
	block, _ := pem.Decode(pemBytes)
	if block == nil {
		return nil, errors.New("Private Key could not be parsed (no key found).")
	}

	var privKey *rsa.PrivateKey
	switch block.Type {
	case "RSA PRIVATE KEY":
		key, err := x509.ParsePKCS1PrivateKey(block.Bytes)
		if err != nil {
			return nil, err
		}
		privKey = key

	default:
		return nil, fmt.Errorf("private Key could not be parsed (unsupported type %q", block.Type)
	}
	return privKey, nil
}

func loadRSAPrivateKey(path string) (*rsa.PrivateKey, error) {
	data, err := ioutil.ReadFile(path)
	if err != nil {
		return nil, err
	}
	return parseRSAPrivateKey(data)
}

func EncryptArtifact(AESKeyPath string, artifact UpdateArtifact) ([]byte, []byte, []byte, error) {

	key := make([]byte, 16)

	if _, err := io.ReadFull(rand.Reader, key); err != nil {
		return nil, nil, nil, err
	}
	ciph, err := aes.NewCipher(key)
	if err != nil {
		return nil, nil, nil, err
	}
	gcm, err := cipher.NewGCM(ciph)
	if err != nil {
		return nil, nil, nil, err
	}

	nonce := make([]byte, gcm.NonceSize())
	if _, err := io.ReadFull(rand.Reader, nonce); err != nil {
		return nil, nil, nil, err
	}

	fwImageBytes, err := ioutil.ReadFile(artifact.PayloadPath)
	if err != nil {
		return nil, nil, nil, err
	}

	var cipherText []byte
	var artifactBlob []byte

	artifactBlob = append(artifactBlob, artifact.Header.Signature[:]...)
	artifactBlob = append(artifactBlob, artifact.Header.SequenceNumber[:]...)
	artifactBlob = append(artifactBlob, artifact.Header.HardwareUUID[:]...)
	artifactBlob = append(artifactBlob, artifact.Header.URILength[:]...)
	artifactBlob = append(artifactBlob, artifact.Header.URIData[:]...)
	artifactBlob = append(artifactBlob, fwImageBytes[:]...)

	cipherText = gcm.Seal(cipherText, nonce, artifactBlob, nil)

	return cipherText, nonce, key, nil
}
