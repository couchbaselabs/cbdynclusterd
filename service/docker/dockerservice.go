package docker

import (
	"context"
	"log"
	"strconv"

	"github.com/couchbaselabs/cbdynclusterd/cluster"
	"github.com/couchbaselabs/cbdynclusterd/dyncontext"
	"github.com/couchbaselabs/cbdynclusterd/helper"
	"github.com/couchbaselabs/cbdynclusterd/service"
	"github.com/couchbaselabs/cbdynclusterd/service/common"
	"github.com/couchbaselabs/cbdynclusterd/store"
	"github.com/docker/docker/api/types"
	"github.com/docker/docker/api/types/network"
	"github.com/docker/docker/client"
	"github.com/pkg/errors"
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

func (ds *DockerService) AllocateCluster(ctx context.Context, opts service.AllocateClusterOptions) (string, error) {
	log.Printf("Allocating cluster (requested by: %s)", dyncontext.ContextUser(ctx))

	if len(opts.Nodes) == 0 {
		return "", errors.New("must specify at least a single node for the cluster")
	}
	if len(opts.Nodes) > 10 {
		return "", errors.New("cannot allocate clusters with more than 10 nodes")
	}

	if err := common.GetConfigRepo(ds.aliasRepoPath); err != nil {
		log.Printf("Get config failed: %v", err)
		return "", err
	}

	clusterID := helper.NewRandomClusterID()

	nodesToAllocate, err := common.CreateNodesToAllocate(opts.Nodes, ds.aliasRepoPath)

	if err != nil {
		return "", err
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
		go func(clusterID string, node common.NodeOptions) {
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
	return common.KillAllClusters(ctx, ds)
}

func (ds *DockerService) EnsureImageExists(ctx context.Context, serverVersion, os, arch string, useCommunity bool) (string, error) {
	nodeVersion, err := common.ParseServerVersion(serverVersion, os, arch, useCommunity)
	if err != nil {
		return "", err
	}

	err = ds.ensureImageExists(ctx, nodeVersion, "")
	if err != nil {
		return "", err
	}

	return nodeVersion.ToImageName(ds.dockerRegistry), nil
}

func (ds *DockerService) AddCollection(ctx context.Context, clusterID string, opts service.AddCollectionOptions) error {
	return common.AddCollection(ctx, ds, clusterID, opts)
}

func (ds *DockerService) SetupCertAuth(ctx context.Context, clusterID string, opts service.SetupClientCertAuthOptions) (*service.CertAuthResult, error) {
	c, err := ds.GetCluster(ctx, clusterID)
	if err != nil {
		return nil, err
	}

	initialNodes := c.Nodes
	var nodes []Node
	var clusterVersion = initialNodes[0].InitialServerVersion
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

	return ds.setupCertAuth(opts.UserName, opts.UserEmail, nodes, clusterVersion, opts.NumRoots)
}

func (ds *DockerService) AddBucket(ctx context.Context, clusterID string, opts service.AddBucketOptions) error {
	return common.AddBucket(ctx, ds, clusterID, opts)
}

func (ds *DockerService) AddSampleBucket(ctx context.Context, clusterID string, opts service.AddSampleOptions) error {
	return common.AddSampleBucket(ctx, ds, clusterID, opts)
}

func (ds *DockerService) AddUser(ctx context.Context, clusterID string, user *helper.UserOption, bucket string) error {
	return errors.New("not supported")
}

func (ds *DockerService) AddIP(ctx context.Context, clusterID, ip string) error {
	return errors.New("not supported")
}

func (ds *DockerService) ConnString(ctx context.Context, clusterID string, useSSL bool) (string, error) {
	return common.ConnString(ctx, ds, clusterID, useSSL)
}
