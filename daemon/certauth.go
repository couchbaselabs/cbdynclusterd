package daemon

import (
	"crypto/rand"
	"crypto/rsa"
	"crypto/x509"
	"encoding/pem"
	"fmt"
	"strconv"
	"time"

	"github.com/couchbaselabs/cbcerthelper"

	"github.com/couchbaselabs/cbdynclusterd/cluster"
	"github.com/couchbaselabs/cbdynclusterd/helper"
)

type SetupClientCertAuthOptions struct {
	Nodes []*Node
	Conf  SetupClientCertAuthJSON
}

type CertAuthResult struct {
	CACert     []byte
	ClientKey  []byte
	ClientCert []byte
}

func SetupCertAuth(opts SetupClientCertAuthOptions) (*CertAuthResult, error) {
	initialNodes := opts.Nodes
	var nodes []cluster.Node
	for i := 0; i < len(initialNodes); i++ {
		ipv4 := initialNodes[i].IPv4Address
		hostname := ipv4

		nodeHost := cluster.Node{
			HostName:  hostname,
			Port:      strconv.Itoa(helper.RestPort),
			SshLogin:  &helper.Cred{Username: helper.SshUser, Password: helper.SshPass, Hostname: ipv4, Port: helper.SshPort},
			RestLogin: &helper.Cred{Username: helper.RestUser, Password: helper.RestPass, Hostname: ipv4, Port: helper.RestPort},
		}
		nodes = append(nodes, nodeHost)
	}

	return setupCertAuth(opts.Conf.UserName, opts.Conf.UserEmail, nodes)
}

func setupCertAuth(username, email string, nodes []cluster.Node) (*CertAuthResult, error) {
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

	return &CertAuthResult{
		CACert:     rootOut,
		ClientKey:  keyOut,
		ClientCert: clientOut,
	}, nil
}
