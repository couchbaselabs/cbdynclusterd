package docker

import (
	"crypto/rand"
	"crypto/rsa"
	"crypto/x509"
	"encoding/pem"
	"fmt"
	"github.com/couchbaselabs/cbcerthelper"
	"github.com/couchbaselabs/cbdynclusterd/service"
	"time"
)

func (ds *DockerService) setupCertAuth(username, email string, nodes []Node) (*service.CertAuthResult, error) {
	rootKey, err := rsa.GenerateKey(rand.Reader, 2048)
	if err != nil {
		return nil, fmt.Errorf("failed to generate private key: %v", err)
	}

	now := time.Now()

	rootCert, rootCertBytes, err := cbcerthelper.CreateRootCert(now, now.Add(3650*24*time.Hour), rootKey)
	if err != nil {
		return nil, fmt.Errorf("failed to generate root cert: %v", err)
	}

	for _, node := range nodes {
		if err := node.SetupCert(rootCert, rootKey, now); err != nil {
			return nil, err
		}
	}

	clientKey, err := rsa.GenerateKey(rand.Reader, 2048)
	if err != nil {
		return nil, fmt.Errorf("failed to generate private key: %v", err)
	}

	clientCSR, _, err := cbcerthelper.CreateClientCertReq(username, clientKey)
	if err != nil {
		return nil, err
	}

	_, clientCertBytes, err := cbcerthelper.CreateClientCert(now, now.Add(365*24*time.Hour), rootKey, rootCert,
		clientCSR, email)
	if err != nil {
		return nil, err
	}

	rootOut := pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: rootCertBytes})
	keyOut := pem.EncodeToMemory(&pem.Block{Type: "RSA PRIVATE KEY", Bytes: x509.MarshalPKCS1PrivateKey(clientKey)})
	clientOut := pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: clientCertBytes})

	return &service.CertAuthResult{
		CACert:     rootOut,
		ClientKey:  keyOut,
		ClientCert: clientOut,
	}, nil
}
