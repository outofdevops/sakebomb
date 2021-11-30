// Copyright 2021 OutOfDevOps. All rights reserved.
// Use of this source code is governed by a MIT license
// that can be found in the LICENSE file.

// Package certs implements helper functions to generate X.509 certificates
//
package certs

import (
	"bytes"
	"crypto/rand"
	"crypto/rsa"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/pem"
	"errors"
	"fmt"
	"math/big"
	"time"
)

// GenerateKeysAndCertExpiringIn gets the time in minutes and returns

func GenerateKeysAndCertExpiringIn(minutes int) (public []byte, private []byte, err error) {
	privateKey, err := rsa.GenerateKey(rand.Reader, 2048)
	if err != nil {
		return nil, nil, fmt.Errorf("failed to generate RSA keypair: %v", err)
	}

	notBefore := time.Now()
	notAfter := notBefore.Add(time.Duration(minutes) * time.Minute)

	template, err := certTemplate(notBefore, notAfter)
	if err != nil {
		return nil, nil, err
	}

	derBytes, err := x509.CreateCertificate(rand.Reader, &template, &template, &privateKey.PublicKey, privateKey)
	if err != nil {
		return nil, nil, fmt.Errorf("failed to create x509 cert: %v", err)
	}

	var certEncoded bytes.Buffer
	if err := pem.Encode(&certEncoded, &pem.Block{Type: "CERTIFICATE", Bytes: derBytes}); err != nil {
		return nil, nil, fmt.Errorf("failed to PEM encode certificate")
	}


	privateKeyBytes, err := x509.MarshalPKCS8PrivateKey(privateKey)
	if err != nil {
		return nil, nil, fmt.Errorf("failed to marshal PKCS8PrivateKey: %v", err)
	}
	privateKeyBlock := &pem.Block{
		Type:  "PRIVATE KEY",
		Bytes: privateKeyBytes,
	}

	buf := new(bytes.Buffer)
	pem.Encode(buf, privateKeyBlock)
	return certEncoded.Bytes(), buf.Bytes(), nil
}

func certTemplate(notBefore time.Time, notAfter time.Time) (x509.Certificate, error) {
	if notAfter.Before(notBefore) {
		return x509.Certificate{}, errors.New("invalid: notAfter must be > notBefore")
	}
	serialNumberLimit := new(big.Int).Lsh(big.NewInt(1), 128)
	serialNumber, _ := rand.Int(rand.Reader, serialNumberLimit)

	template := x509.Certificate{
		SerialNumber: serialNumber,
		Subject: pkix.Name{
			CommonName: "unused",
		},
		NotBefore: notBefore,
		NotAfter:  notAfter,

		KeyUsage:              x509.KeyUsageDigitalSignature | x509.KeyUsageKeyEncipherment,
		ExtKeyUsage:           []x509.ExtKeyUsage{x509.ExtKeyUsageServerAuth},
		BasicConstraintsValid: true,
	}

	return template, nil
}
