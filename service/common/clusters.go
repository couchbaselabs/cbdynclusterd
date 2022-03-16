package common

import (
	"context"
	"errors"
	"fmt"
	"log"
	"strconv"
	"strings"

	"github.com/couchbaselabs/cbdynclusterd/cluster"
	"github.com/couchbaselabs/cbdynclusterd/dyncontext"
	"github.com/couchbaselabs/cbdynclusterd/helper"
	"github.com/couchbaselabs/cbdynclusterd/service"
)

func SetupCluster(opts ClusterSetupOptions) (string, error) {
	services := opts.Services

	initialNodes := opts.Nodes
	var nodes []*Node
	for i := 0; i < len(services); i++ {
		ipv4 := initialNodes[i].IPv4Address
		hostname := ipv4
		if opts.UseIpv6 {
			hostname = initialNodes[i].IPv6Address
		}

		nodeHost := &Node{
			HostName:  hostname,
			Port:      strconv.Itoa(helper.RestPort),
			SshLogin:  &helper.Cred{Username: helper.SshUser, Password: helper.SshPass, Hostname: ipv4, Port: helper.SshPort},
			RestLogin: &helper.Cred{Username: helper.RestUser, Password: helper.RestPass, Hostname: ipv4, Port: helper.RestPort},
			N1qlLogin: &helper.Cred{Username: helper.RestUser, Password: helper.RestPass, Hostname: ipv4, Port: helper.N1qlPort},
			FtsLogin:  &helper.Cred{Username: helper.RestUser, Password: helper.RestPass, Hostname: ipv4, Port: helper.FtsPort},
			Services:  services[i],
		}
		nodes = append(nodes, nodeHost)
	}

	config := Config{
		MemoryQuota:   opts.MemoryQuota,
		StorageMode:   opts.StorageMode,
		User:          opts.User,
		Bucket:        opts.Bucket,
		UseHostname:   opts.UseHostname,
		UseDevPreview: opts.UseDeveloperPreview,
	}

	clusterManager := &Manager{
		Nodes:  nodes,
		Config: config,
	}

	return clusterManager.StartCluster()
}

func ConnString(ctx context.Context, s service.ClusterService, clusterID string, useSSL bool) (string, error) {
	c, err := s.GetCluster(ctx, clusterID)
	if err != nil {
		return "", err
	}

	var addresses []string
	for _, node := range c.Nodes {
		addresses = append(addresses, node.IPv4Address)
	}

	scheme := "couchbase"
	if useSSL {
		scheme = "couchbases"
	}

	return fmt.Sprintf("%s://%s", scheme, strings.Join(addresses, ",")), nil
}

func AddSampleBucket(ctx context.Context, s service.ClusterService, clusterID string, opts service.AddSampleOptions) error {
	log.Printf("Loading sample bucket %s to cluster %s (requested by: %s)", opts.SampleBucket, clusterID, dyncontext.ContextUser(ctx))

	c, err := s.GetCluster(ctx, clusterID)
	if err != nil {
		return err
	}

	if helper.SampleBucketsCount[opts.SampleBucket] == 0 {
		return errors.New("Unknown sample bucket")
	}

	if len(c.Nodes) == 0 {
		return errors.New("no nodes available")
	}

	n := c.Nodes[0]
	ipv4 := n.IPv4Address
	hostname := ipv4
	if opts.UseHostname {
		hostname = n.ContainerName[1:] + helper.DomainPostfix
	}

	node := &Node{
		HostName:  hostname,
		Port:      strconv.Itoa(helper.GetRestPort(opts.UseSecure)),
		SshLogin:  &helper.Cred{Username: helper.SshUser, Password: helper.SshPass, Hostname: ipv4, Port: helper.SshPort},
		RestLogin: &helper.Cred{Username: helper.RestUser, Password: helper.RestPass, Hostname: ipv4, Port: helper.GetRestPort(opts.UseSecure), Secure: opts.UseSecure},
	}

	return node.LoadSample(opts.SampleBucket)
}

func AddBucket(ctx context.Context, s service.ClusterService, clusterID string, opts service.AddBucketOptions) error {
	log.Printf("Adding bucket %s to cluster %s (requested by: %s)", opts.Name, clusterID, dyncontext.ContextUser(ctx))

	c, err := s.GetCluster(ctx, clusterID)
	if err != nil {
		return err
	}

	if len(c.Nodes) == 0 {
		return errors.New("no nodes available")
	}

	n := c.Nodes[0]
	ipv4 := n.IPv4Address
	hostname := ipv4
	if opts.UseHostname {
		hostname = n.ContainerName[1:] + helper.DomainPostfix
	}

	node := &Node{
		HostName:  hostname,
		Port:      strconv.Itoa(helper.GetRestPort(opts.UseSecure)),
		SshLogin:  &helper.Cred{Username: helper.SshUser, Password: helper.SshPass, Hostname: ipv4, Port: helper.SshPort},
		RestLogin: &helper.Cred{Username: helper.RestUser, Password: helper.RestPass, Hostname: ipv4, Port: helper.GetRestPort(opts.UseSecure), Secure: opts.UseSecure},
		Version:   n.InitialServerVersion,
	}

	return node.CreateBucket(&cluster.Bucket{
		Name:              opts.Name,
		Type:              opts.BucketType,
		ReplicaCount:      opts.ReplicaCount,
		RamQuotaMB:        strconv.Itoa(opts.RamQuota),
		EphEvictionPolicy: opts.EvictionPolicy,
		StorageBackend:    opts.StorageBackend,
	})
}

func SetupCertAuth(ctx context.Context, s service.ClusterService, clusterID string, opts service.SetupClientCertAuthOptions) (*service.CertAuthResult, error) {
	c, err := s.GetCluster(ctx, clusterID)
	if err != nil {
		return nil, err
	}

	initialNodes := c.Nodes
	clusterVersion := initialNodes[0].InitialServerVersion
	var nodes []Node
	for i := 0; i < len(initialNodes); i++ {
		ipv4 := initialNodes[i].IPv4Address
		hostname := ipv4
		sshUsername := helper.SshUser
		if opts.SSHUsername != "" {
			sshUsername = opts.SSHUsername
		}
		nodeHost := Node{
			HostName:  hostname,
			Port:      strconv.Itoa(helper.RestPort),
			SshLogin:  &helper.Cred{Username: sshUsername, Password: helper.SshPass, Hostname: ipv4, Port: helper.SshPort, KeyPath: opts.SSHKeyPath},
			RestLogin: &helper.Cred{Username: helper.RestUser, Password: helper.RestPass, Hostname: ipv4, Port: helper.RestPort},
		}
		nodes = append(nodes, nodeHost)
	}

	return setupCertAuth(opts.UserName, opts.UserEmail, nodes, clusterVersion, opts.NumRoots)
}

func SetupClusterEncryption(ctx context.Context, s service.ClusterService, clusterID string, opts service.SetupClusterEncryptionOptions) error {
	c, err := s.GetCluster(ctx, clusterID)
	if err != nil {
		return err
	}

	initialNodes := c.Nodes
	var nodes []Node
	for i := 0; i < len(initialNodes); i++ {
		ipv4 := initialNodes[i].IPv4Address
		hostname := ipv4

		nodeHost := Node{
			HostName:  hostname,
			Port:      strconv.Itoa(helper.GetRestPort(opts.UseSecure)),
			SshLogin:  &helper.Cred{Username: helper.SshUser, Password: helper.SshPass, Hostname: ipv4, Port: helper.SshPort},
			RestLogin: &helper.Cred{Username: helper.RestUser, Password: helper.RestPass, Hostname: ipv4, Port: helper.GetRestPort(opts.UseSecure), Secure: opts.UseSecure},
		}
		nodes = append(nodes, nodeHost)
	}

	return setupClusterEncryption(nodes, opts)
}

func AddCollection(ctx context.Context, s service.ClusterService, clusterID string, opts service.AddCollectionOptions) error {
	log.Printf("Adding collection %s to bucket %s on cluster %s (requested by: %s)", opts.Name,
		opts.BucketName, clusterID, dyncontext.ContextUser(ctx))

	c, err := s.GetCluster(ctx, clusterID)
	if err != nil {
		return err
	}

	if len(c.Nodes) == 0 {
		return errors.New("no nodes available")
	}

	n := c.Nodes[0]
	ipv4 := n.IPv4Address
	hostname := ipv4
	if opts.UseHostname {
		hostname = n.ContainerName[1:] + helper.DomainPostfix
	}

	node := &Node{
		HostName:  hostname,
		Port:      strconv.Itoa(helper.GetRestPort(opts.UseSecure)),
		SshLogin:  &helper.Cred{Username: helper.SshUser, Password: helper.SshPass, Hostname: ipv4, Port: helper.SshPort},
		RestLogin: &helper.Cred{Username: helper.RestUser, Password: helper.RestPass, Hostname: ipv4, Port: helper.GetRestPort(opts.UseSecure), Secure: opts.UseSecure},
	}

	return node.CreateCollection(&cluster.Collection{
		Name:       opts.Name,
		ScopeName:  opts.ScopeName,
		BucketName: opts.BucketName,
	})
}

func KillAllClusters(ctx context.Context, s service.ClusterService) error {
	clusters, err := s.GetAllClusters(ctx)
	if err != nil {
		return err
	}

	var clustersToKill []string

	for _, c := range clusters {
		clustersToKill = append(clustersToKill, c.ID)
	}

	signal := make(chan error)

	for _, clusterID := range clustersToKill {
		go func(clusterID string) {
			signal <- s.KillCluster(ctx, clusterID)
		}(clusterID)
	}

	var killError error
	for range clustersToKill {
		err := <-signal
		if err != nil && killError == nil {
			killError = err
		}
	}
	if killError != nil {
		return killError
	}

	return nil
}

func AddUser(ctx context.Context, s service.ClusterService, clusterID string, opts service.AddUserOptions) error {
	log.Printf("Adding user %s on cluster %s (requested by: %s)", opts.User.Name, clusterID, dyncontext.ContextUser(ctx))

	c, err := s.GetCluster(ctx, clusterID)
	if err != nil {
		return err
	}

	if len(c.Nodes) == 0 {
		return errors.New("no nodes available")
	}

	hostname := c.Nodes[0].IPv4Address

	node := &Node{
		HostName:  hostname,
		Port:      strconv.Itoa(helper.GetRestPort(opts.UseSecure)),
		SshLogin:  &helper.Cred{Username: helper.SshUser, Password: helper.SshPass, Hostname: hostname, Port: helper.SshPort},
		RestLogin: &helper.Cred{Username: helper.RestUser, Password: helper.RestPass, Hostname: hostname, Port: helper.GetRestPort(opts.UseSecure), Secure: opts.UseSecure},
	}

	return node.CreateUser(opts.User)
}
