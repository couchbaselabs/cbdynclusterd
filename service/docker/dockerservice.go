package docker

import (
	"context"
	"fmt"
	"github.com/couchbaselabs/cbdynclusterd/cluster"
	"github.com/couchbaselabs/cbdynclusterd/dyncontext"
	"github.com/couchbaselabs/cbdynclusterd/helper"
	"github.com/couchbaselabs/cbdynclusterd/service"
	"github.com/couchbaselabs/cbdynclusterd/store"
	"github.com/docker/docker/api/types"
	"github.com/docker/docker/api/types/network"
	"github.com/docker/docker/client"
	"github.com/pkg/errors"
	"log"
	"strconv"
	"strings"
)

type DockerService struct {
	docker         *client.Client
	dockerRegistry string
	dnsSvcHost     string
	metaStore      *store.ReadOnlyMetaDataStore
	aliasRepoPath  string
}

func NewDockerService(d *client.Client, dockerRegistry, dnsSvcHost, aliasRepoPath string, metaStore *store.ReadOnlyMetaDataStore) *DockerService {
	return &DockerService{
		docker:         d,
		dockerRegistry: dockerRegistry,
		dnsSvcHost:     dnsSvcHost,
		metaStore:      metaStore,
		aliasRepoPath:  aliasRepoPath,
	}
}

func (ds *DockerService) GetCluster(ctx context.Context, clusterID string) (*cluster.Cluster, error) {
	log.Printf("Running docker GetCluster (requested by: %s)", dyncontext.ContextUser(ctx))

	clusters, err := ds.GetAllClusters(ctx)
	if err != nil {
		return nil, err
	}

	for _, c := range clusters {
		if c.ID == clusterID {
			return c, nil
		}
	}

	return nil, errors.New("cluster not found")
}

func (ds *DockerService) GetAllClusters(ctx context.Context) ([]*cluster.Cluster, error) {
	log.Printf("Running docker GetAllClusters (requested by: %s)", dyncontext.ContextUser(ctx))

	containers, err := ds.docker.ContainerList(ctx, types.ContainerListOptions{
		All: true,
	})
	if err != nil {
		return nil, err
	}

	clusterMap := make(map[string][]types.Container)

	for _, container := range containers {
		clusterID := container.Labels["com.couchbase.dyncluster.cluster_id"]
		if clusterID != "" {
			clusterMap[clusterID] = append(clusterMap[clusterID], container)
		}
	}

	var clusters []*cluster.Cluster
	for clusterID, containers := range clusterMap {
		meta, err := ds.metaStore.GetClusterMeta(clusterID)
		if err != nil {
			log.Printf("Encountered unregistered cluster: %s", clusterID)
			continue
		}

		clusterCreator := ""

		var nodes []*cluster.Node
		for _, container := range containers {
			eth0Net := container.NetworkSettings.Networks[NetworkName]
			if eth0Net == nil {
				// This is a little hack to make sure weird stuff doesn't stop the node
				// from showing up in the nodes list
				fakeNet := network.EndpointSettings{}
				eth0Net = &fakeNet
			}

			containerCreator := container.Labels["com.couchbase.dyncluster.creator"]
			if clusterCreator == "" {
				clusterCreator = containerCreator
			}

			nodes = append(nodes, &cluster.Node{
				ContainerID:          container.ID[0:12],
				ContainerName:        container.Names[0],
				State:                container.State,
				Name:                 container.Labels["com.couchbase.dyncluster.node_name"],
				InitialServerVersion: container.Labels["com.couchbase.dyncluster.initial_server_version"],
				IPv4Address:          eth0Net.IPAddress,
				IPv6Address:          eth0Net.GlobalIPv6Address,
			})
		}

		if clusterCreator == "" {
			clusterCreator = "unknown"
		}

		// Don't include clusters that we don't actually own
		if !dyncontext.ContextIgnoreOwnership(ctx) && clusterCreator != dyncontext.ContextUser(ctx) {
			continue
		}

		clusters = append(clusters, &cluster.Cluster{
			ID:      clusterID,
			Creator: clusterCreator,
			Owner:   meta.Owner,
			Timeout: meta.Timeout,
			Nodes:   nodes,
		})
	}

	return clusters, nil
}

func (ds *DockerService) AllocateCluster(ctx context.Context, opts AllocateClusterOptions) (string, error) {
	log.Printf("Allocating cluster (requested by: %s)", dyncontext.ContextUser(ctx))

	if len(opts.Nodes) == 0 {
		return "", errors.New("must specify at least a single node for the cluster")
	}
	if len(opts.Nodes) > 10 {
		return "", errors.New("cannot allocate clusters with more than 10 nodes")
	}

	if err := ds.getConfigRepo(); err != nil {
		log.Printf("Get config failed: %v", err)
		return "", err
	}

	clusterID := helper.NewRandomClusterID()

	var nodesToAllocate []nodeOptions
	for nodeIdx, node := range opts.Nodes {
		finalVersion, err := ds.aliasServerVersion(node.ServerVersion)
		if err != nil {
			return "", err
		}
		nodeVersion, err := parseServerVersion(finalVersion, node.UseCommunityEdition)
		if err != nil {
			return "", err
		}

		nodeToAllocate := nodeOptions{
			Name:          node.Name,
			Platform:      node.Platform,
			ServerVersion: finalVersion,
			VersionInfo:   nodeVersion,
		}
		if nodeToAllocate.Name == "" {
			nodeToAllocate.Name = fmt.Sprintf("node_%d", nodeIdx+1)
		}

		nodesToAllocate = append(nodesToAllocate, nodeToAllocate)
	}

	if len(nodesToAllocate) > 0 {
		// We assume that all nodes are using the same server version.
		node := nodesToAllocate[0]

		err := ds.ensureImageExists(ctx, node.VersionInfo, clusterID)
		if err != nil {
			return "", err
		}
	}

	signal := make(chan error)

	for _, node := range nodesToAllocate {
		go func(clusterID string, node nodeOptions) {
			_, err := ds.allocateNode(ctx, clusterID, opts.Deadline, node)
			signal <- err
		}(clusterID, node)
	}

	var createError error
	for range nodesToAllocate {
		err := <-signal
		if err != nil && createError == nil {
			createError = err
		}
	}
	if createError != nil {
		ds.KillCluster(ctx, clusterID)
		return "", createError
	}

	return clusterID, nil
}

func (ds *DockerService) KillCluster(ctx context.Context, clusterID string) error {
	log.Printf("Killing docker cluster %s (requested by: %s)", clusterID, dyncontext.ContextUser(ctx))

	c, err := ds.GetCluster(ctx, clusterID)
	if err != nil {
		return err
	}

	if !dyncontext.ContextIgnoreOwnership(ctx) && c.Owner != dyncontext.ContextUser(ctx) {
		return errors.New("cannot kill clusters you don't own")
	}

	var nodesToKill []string
	for _, node := range c.Nodes {
		nodesToKill = append(nodesToKill, node.ContainerID)
	}

	signal := make(chan error)

	for _, nodeID := range nodesToKill {
		go func(nodeID string) {
			signal <- ds.killNode(ctx, nodeID)
		}(nodeID)
	}

	var killError error
	for range nodesToKill {
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

func (ds *DockerService) KillAllClusters(ctx context.Context) error {
	log.Printf("Killing all docker clusters")

	var clustersToKill []string

	clusters, err := ds.GetAllClusters(ctx)
	if err != nil {
		return err
	}

	for _, c := range clusters {
		clustersToKill = append(clustersToKill, c.ID)
	}

	signal := make(chan error)

	for _, clusterID := range clustersToKill {
		go func(clusterID string) {
			signal <- ds.KillCluster(ctx, clusterID)
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

func (ds *DockerService) EnsureImageExists(ctx context.Context, serverVersion string, useCommunity bool) (string, error) {
	nodeVersion, err := parseServerVersion(serverVersion, useCommunity)
	if err != nil {
		return "", err
	}

	err = ds.ensureImageExists(ctx, nodeVersion, "")
	if err != nil {
		return "", err
	}

	return nodeVersion.toImageName(ds.dockerRegistry), nil
}

func (ds *DockerService) SetupCluster(opts ClusterSetupOptions) (string, error) {
	services := opts.Services

	initialNodes := opts.Nodes
	var nodes []*Node
	for i := 0; i < len(services); i++ {
		ipv4 := initialNodes[i].IPv4Address
		hostname := ipv4
		if opts.UseHostname {
			hostname = initialNodes[i].ContainerName[1:] + helper.DomainPostfix
		} else if opts.UseIpv6 {
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

func (ds *DockerService) AddCollection(ctx context.Context, clusterID string, opts service.AddCollectionOptions) error {
	log.Printf("Adding collection %s to bucket %s on cluster %s (requested by: %s)", opts.Name,
		opts.BucketName, clusterID, dyncontext.ContextUser(ctx))

	c, err := ds.GetCluster(ctx, clusterID)
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
		Port:      strconv.Itoa(helper.RestPort),
		SshLogin:  &helper.Cred{Username: helper.SshUser, Password: helper.SshPass, Hostname: ipv4, Port: helper.SshPort},
		RestLogin: &helper.Cred{Username: helper.RestUser, Password: helper.RestPass, Hostname: ipv4, Port: helper.RestPort},
	}

	return node.CreateCollection(&cluster.Collection{
		Name:       opts.Name,
		ScopeName:  opts.ScopeName,
		BucketName: opts.BucketName,
	})
}

func (ds *DockerService) SetupCertAuth(ctx context.Context, clusterID string, opts service.SetupClientCertAuthOptions) (*service.CertAuthResult, error) {
	c, err := ds.GetCluster(ctx, clusterID)
	if err != nil {
		return nil, err
	}

	initialNodes := c.Nodes
	var nodes []Node
	for i := 0; i < len(initialNodes); i++ {
		ipv4 := initialNodes[i].IPv4Address
		hostname := ipv4

		nodeHost := Node{
			HostName:  hostname,
			Port:      strconv.Itoa(helper.RestPort),
			SshLogin:  &helper.Cred{Username: helper.SshUser, Password: helper.SshPass, Hostname: ipv4, Port: helper.SshPort},
			RestLogin: &helper.Cred{Username: helper.RestUser, Password: helper.RestPass, Hostname: ipv4, Port: helper.RestPort},
		}
		nodes = append(nodes, nodeHost)
	}

	return ds.setupCertAuth(opts.UserName, opts.UserEmail, nodes)
}

func (ds *DockerService) AddBucket(ctx context.Context, clusterID string, opts service.AddBucketOptions) error {
	log.Printf("Adding bucket %s to cluster %s (requested by: %s)", opts.Name, clusterID, dyncontext.ContextUser(ctx))

	c, err := ds.GetCluster(ctx, clusterID)
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
		Port:      strconv.Itoa(helper.RestPort),
		SshLogin:  &helper.Cred{Username: helper.SshUser, Password: helper.SshPass, Hostname: ipv4, Port: helper.SshPort},
		RestLogin: &helper.Cred{Username: helper.RestUser, Password: helper.RestPass, Hostname: ipv4, Port: helper.RestPort},
	}

	return node.CreateBucket(&cluster.Bucket{
		Name:              opts.Name,
		Type:              opts.BucketType,
		ReplicaCount:      opts.ReplicaCount,
		RamQuotaMB:        strconv.Itoa(opts.RamQuota),
		EphEvictionPolicy: opts.EvictionPolicy,
	})
}

func (ds *DockerService) AddSampleBucket(ctx context.Context, clusterID string, opts service.AddSampleOptions) error {
	log.Printf("Loading sample bucket %s to cluster %s (requested by: %s)", opts.SampleBucket, clusterID, dyncontext.ContextUser(ctx))

	if helper.SampleBucketsCount[opts.SampleBucket] == 0 {
		return errors.New("Unknown sample bucket")
	}

	c, err := ds.GetCluster(ctx, clusterID)
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
		Port:      strconv.Itoa(helper.RestPort),
		SshLogin:  &helper.Cred{Username: helper.SshUser, Password: helper.SshPass, Hostname: ipv4, Port: helper.SshPort},
		RestLogin: &helper.Cred{Username: helper.RestUser, Password: helper.RestPass, Hostname: ipv4, Port: helper.RestPort},
	}

	return node.LoadSample(opts.SampleBucket)
}

func (ds *DockerService) AddUser(ctx context.Context, clusterID string, user *helper.UserOption, bucket string) error {
	return errors.New("not supported")
}

func (ds *DockerService) AddIP(ctx context.Context, clusterID, ip string) error {
	return errors.New("not supported")
}

func (ds *DockerService) ConnString(ctx context.Context, clusterID string, useSSL bool) (string, error) {
	c, err := ds.GetCluster(ctx, clusterID)
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
