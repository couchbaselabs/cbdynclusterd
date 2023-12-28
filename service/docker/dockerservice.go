package docker

import (
	"context"
	"log"
	"sync"

	"github.com/couchbaselabs/cbdynclusterd/cluster"
	"github.com/couchbaselabs/cbdynclusterd/dyncontext"
	"github.com/couchbaselabs/cbdynclusterd/service"
	"github.com/couchbaselabs/cbdynclusterd/service/common"
	"github.com/couchbaselabs/cbdynclusterd/store"
	"github.com/docker/docker/api/types"
	"github.com/docker/docker/api/types/network"
	"github.com/docker/docker/client"
	"github.com/pkg/errors"
)

type DockerConfig struct {
	// Docker host where containers are running (i.e. tcp://127.0.0.1:2376)
	Host string `toml:"host"`
	// Docker registry to pull/push images
	Registry string `toml:"registry"`
	// Max number of contains to allocate concurrently
	MaxContainers int32 `toml:"max-containers"`
}

type DockerService struct {
	docker         *client.Client
	dockerRegistry string
	metaStore      *store.ReadOnlyMetaDataStore
	aliasRepoPath  string

	mu            sync.Mutex
	reserved      map[string]int
	maxContainers int32
}

func NewDockerService(d *client.Client, aliasRepoPath string, config DockerConfig, metaStore *store.ReadOnlyMetaDataStore) *DockerService {
	return &DockerService{
		docker:         d,
		dockerRegistry: config.Registry,
		metaStore:      metaStore,
		aliasRepoPath:  aliasRepoPath,
		maxContainers:  config.MaxContainers,
		reserved:       make(map[string]int),
	}
}

func (ds *DockerService) clearReservation(clusterID string) {
	ds.mu.Lock()
	defer ds.mu.Unlock()

	delete(ds.reserved, clusterID)
}

func (ds *DockerService) reserve(clusterID string, count int) error {
	ds.mu.Lock()
	defer ds.mu.Unlock()

	// unlimited
	if ds.maxContainers == -1 {
		return nil
	}

	systemCtx := dyncontext.NewContext(context.Background(), "system", true)
	clusters, err := ds.GetAllClusters(systemCtx)
	if err != nil {
		return err
	}

	// count reserved
	reserved := 0
	for _, c := range ds.reserved {
		reserved += c
	}

	// count active
	active := 0
	for _, c := range clusters {
		num := len(c.Nodes)
		active += num

		// clusters can exist before reserved count is decremented
		// so remove any matching active nodes from reserved count
		if _, exists := ds.reserved[c.ID]; exists {
			reserved -= num
		}
	}

	if reserved+active+count > int(ds.maxContainers) {
		return service.MaxCapacityError
	}

	ds.reserved[clusterID] = count

	return nil
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
				ContainerName:        container.Names[0][1:], // remove the / from the beginning
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

func (ds *DockerService) AllocateCluster(ctx context.Context, opts service.AllocateClusterOptions) error {
	log.Printf("Allocating cluster (requested by: %s)", dyncontext.ContextUser(ctx))

	if len(opts.Nodes) == 0 {
		return errors.New("must specify at least a single node for the cluster")
	}
	if len(opts.Nodes) > 10 {
		return errors.New("cannot allocate clusters with more than 10 nodes")
	}

	if err := common.GetConfigRepo(ctx, ds.aliasRepoPath); err != nil {
		log.Printf("Get config failed: %v", err)
		return err
	}

	nodesToAllocate, err := common.CreateNodesToAllocate(opts.Nodes, ds.aliasRepoPath)

	if err != nil {
		return err
	}

	if len(nodesToAllocate) > 0 {
		// We assume that all nodes are using the same server version.
		node := nodesToAllocate[0]

		err := ds.ensureImageExists(ctx, node.VersionInfo, opts.ClusterID)
		if err != nil {
			return err
		}
	}

	err = ds.reserve(opts.ClusterID, len(nodesToAllocate))
	if err != nil {
		return err
	}

	signal := make(chan error)

	for _, node := range nodesToAllocate {
		go func(clusterID string, node common.NodeOptions) {
			_, err := ds.allocateNode(ctx, clusterID, opts.Deadline, node)
			signal <- err
		}(opts.ClusterID, node)
	}

	var createError error
	for range nodesToAllocate {
		err := <-signal
		if err != nil && createError == nil {
			createError = err
		}
	}

	ds.clearReservation(opts.ClusterID)

	if createError != nil {
		ds.KillCluster(ctx, opts.ClusterID)
		return createError
	}

	return nil
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

func (ds *DockerService) EnsureImageExists(ctx context.Context, serverVersion, os, arch string, useCommunity, serverlessMode bool) (string, error) {
	nodeVersion, err := common.ParseServerVersion(serverVersion, os, arch, useCommunity, serverlessMode)
	if err != nil {
		return "", err
	}

	err = ds.ensureImageExists(ctx, nodeVersion, "")
	if err != nil {
		return "", err
	}

	return nodeVersion.ToImageName(ds.dockerRegistry), nil
}

func (ds *DockerService) AddCollection(ctx context.Context, clusterID string, opts service.AddCollectionOptions, connCtx service.ConnectContext) error {
	return common.AddCollection(ctx, ds, clusterID, opts, connCtx)
}

func (ds *DockerService) SetupCertAuth(ctx context.Context, clusterID string, opts service.SetupClientCertAuthOptions, connCtx service.ConnectContext) (*service.CertAuthResult, error) {
	return common.SetupCertAuth(ctx, ds, clusterID, opts, connCtx)
}

func (s *DockerService) SetupClusterEncryption(ctx context.Context, clusterID string, opts service.SetupClusterEncryptionOptions, connCtx service.ConnectContext) error {
	return common.SetupClusterEncryption(ctx, s, clusterID, opts, connCtx)
}

func (ds *DockerService) AddBucket(ctx context.Context, clusterID string, opts service.AddBucketOptions, connCtx service.ConnectContext) error {
	return common.AddBucket(ctx, ds, clusterID, opts, connCtx)
}

func (ds *DockerService) AddSampleBucket(ctx context.Context, clusterID string, opts service.AddSampleOptions, connCtx service.ConnectContext) error {
	return common.AddSampleBucket(ctx, ds, clusterID, opts, connCtx)
}

func (ds *DockerService) AddUser(ctx context.Context, clusterID string, opts service.AddUserOptions, connCtx service.ConnectContext) error {
	return common.AddUser(ctx, ds, clusterID, opts, connCtx)
}

func (ds *DockerService) AddIP(ctx context.Context, clusterID, ip string) error {
	return errors.New("not supported")
}

func (ds *DockerService) ConnString(ctx context.Context, clusterID string, useSSL, useSrv bool) (string, error) {
	if useSrv {
		return "", errors.New("srv not supported for docker service")
	}
	return common.ConnString(ctx, ds, clusterID, useSSL)
}

func (ds *DockerService) RunCBCollect(ctx context.Context, clusterID string) (*service.CBCollectResult, error) {
	return common.RunCBCollect(ctx, ds, clusterID, service.ConnectContext{})
}

func (ds *DockerService) SetupCluster(clusterID string, opts service.ClusterSetupOptions) (string, error) {
	return common.SetupCluster(opts, service.ConnectContext{})
}
