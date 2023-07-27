package cloud

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"io/ioutil"
	"log"
	"math/rand"
	"regexp"
	"strings"
	"time"

	"github.com/couchbaselabs/cbdynclusterd/cluster"
	"github.com/couchbaselabs/cbdynclusterd/dyncontext"
	"github.com/couchbaselabs/cbdynclusterd/helper"
	"github.com/couchbaselabs/cbdynclusterd/service"
	"github.com/couchbaselabs/cbdynclusterd/service/common"
	"github.com/couchbaselabs/cbdynclusterd/store"
)

var (
	// Looks for x.x.x e.g. 7.1.0
	serverVersionFromImageRegex = regexp.MustCompile(`\d\.\d\.\d`)
)

type CapellaConfig struct {
	// URL for Capllea APIs (e.g. cloud.couchbase.com)
	URL string `toml:"url"`
	// Access key to use for Capella public API
	AccessKey string `toml:"access-key"`
	// Private key to use for Capella public API
	PrivateKey string `toml:"private-key"`
	// Project ID to use for Capella APIs
	ProjectID string `toml:"project-id"`
	// Tenant ID to use for Capella APIs
	TenantID string `toml:"tenant-id"`
	// Username to use for Capella internal API
	Username string `toml:"username"`
	// Password to use for Capella internal API
	Password string `toml:"password"`
	// Override token to use to create nonstandard Capella clusters
	OverrideToken string `toml:"override-token"`
}

type CloudService struct {
	defaultEnv *store.CloudEnvironment
	envs       map[string]*store.CloudEnvironment
	enabled    bool
	client     *client
	metaStore  *store.MetaDataStore
}

func envFromConfig(config CapellaConfig) *store.CloudEnvironment {
	return &store.CloudEnvironment{
		TenantID:      config.TenantID,
		ProjectID:     config.ProjectID,
		URL:           config.URL,
		AccessKey:     config.AccessKey,
		SecretKey:     config.PrivateKey,
		Username:      config.Username,
		Password:      config.Password,
		OverrideToken: config.OverrideToken,
	}
}

func NewCloudService(defaultEnvKey string, config map[string]CapellaConfig, metaStore *store.MetaDataStore) *CloudService {
	envs := make(map[string]*store.CloudEnvironment)
	for key, config := range config {
		envs[key] = envFromConfig(config)
	}
	var defaultEnv *store.CloudEnvironment
	if defaultEnvKey != "" {
		env, ok := config[defaultEnvKey]
		if ok {
			defaultEnv = envFromConfig(env)
		}
	}
	enabled := defaultEnv != nil
	log.Printf("Cloud enabled: %t", enabled)
	return &CloudService{
		enabled:    enabled,
		defaultEnv: defaultEnv,
		envs:       envs,
		client:     NewClient(),
		metaStore:  metaStore,
	}
}

func (cs *CloudService) getCluster(ctx context.Context, cloudClusterID string, env *store.CloudEnvironment) (*getClusterJSON, error) {
	res, err := cs.client.Do(ctx, "GET", getClusterPath+cloudClusterID, nil, env)
	if err != nil {
		return nil, err
	}
	defer res.Body.Close()

	if res.StatusCode != 200 {
		bb, err := ioutil.ReadAll(res.Body)
		if err != nil {
			return nil, fmt.Errorf("get cluster failed: reason could not be determined: %v", err)
		}
		return nil, fmt.Errorf("get cluster failed: %s", string(bb))
	}

	bb, err := ioutil.ReadAll(res.Body)
	if err != nil {
		return nil, fmt.Errorf("get cluster succeeded: but body could not be read: %v", err)
	}

	var respBody getClusterJSON
	if err := json.Unmarshal(bb, &respBody); err != nil {
		return nil, err
	}

	return &respBody, nil
}

func (cs *CloudService) addBucket(ctx context.Context, clusterID, cloudClusterID string, opts service.AddBucketOptions, env *store.CloudEnvironment) error {
	log.Printf("Running cloud CreateBucket for %s: %s", clusterID, cloudClusterID)

	body := bucketSpecJSON{
		Name:              opts.Name,
		MemoryQuota:       opts.RamQuota,
		Replicas:          opts.ReplicaCount,
		ConflicResolution: "seqno",
		DurabilityLevel:   "none",
	}

	res, err := cs.client.DoInternal(ctx, "POST", fmt.Sprintf(createBucketPath, env.TenantID, env.ProjectID, cloudClusterID), body, env)
	if err != nil {
		return err
	}
	defer res.Body.Close()

	if res.StatusCode < 200 || res.StatusCode >= 300 {
		bb, err := ioutil.ReadAll(res.Body)
		if err != nil {
			return fmt.Errorf("create bucket failed: reason could not be determined: %v", err)
		}
		errorBody := string(bb)
		// AV-35851: Cluster randomly goes into deploying state after adding IP
		if strings.Contains(errorBody, "ErrClusterStateNotNormal") {
			return cs.addBucket(ctx, clusterID, cloudClusterID, opts, env)
		}
		return fmt.Errorf("create bucket failed: %s", string(bb))
	}

	return nil
}

func (cs *CloudService) addIP(ctx context.Context, clusterID, cloudClusterID, ip string, env *store.CloudEnvironment) error {
	log.Printf("Running cloud AddIP for %s: %s", clusterID, cloudClusterID)

	body := allowListBulkJSON{
		Create: []allowListJSON{
			{
				CIDR: ip,
			},
		},
	}

	res, err := cs.client.DoInternal(ctx, "POST", fmt.Sprintf(addIPPath, env.TenantID, env.ProjectID, cloudClusterID), body, env)
	if err != nil {
		return err
	}
	defer res.Body.Close()

	if res.StatusCode < 200 || res.StatusCode >= 300 {
		bb, err := ioutil.ReadAll(res.Body)
		if err != nil {
			return fmt.Errorf("add ip failed: reason could not be determined: %v", err)
		}
		errorBody := string(bb)
		// AV-35851: Cluster randomly goes into deploying state after adding IP
		if strings.Contains(errorBody, "ErrClusterStateNotNormal") {
			time.Sleep(time.Second * 5)
			return cs.addIP(ctx, clusterID, cloudClusterID, ip, env)
		}
		return fmt.Errorf("add ip failed: %s", string(bb))
	}

	return nil
}

func (cs *CloudService) killCluster(ctx context.Context, clusterID, cloudClusterID string, env *store.CloudEnvironment) error {
	log.Printf("Running cloud KillCluster for %s: %s", clusterID, cloudClusterID)

	res, err := cs.client.Do(ctx, "DELETE", deleteClusterPath+cloudClusterID, nil, env)
	if err != nil {
		return err
	}
	defer res.Body.Close()

	if res.StatusCode < 200 || res.StatusCode >= 300 {
		bb, err := ioutil.ReadAll(res.Body)
		if err != nil {
			log.Printf("failed to kill cluster: %s: %s", clusterID, cloudClusterID)
			return fmt.Errorf("kill cluster failed: reason could not be determined: %v", err)
		}
		log.Printf("failed to kill cluster: %s: %s: %s", clusterID, cloudClusterID, string(bb))
		return fmt.Errorf("kill cluster failed: %s", string(bb))
	}

	return nil
}

func (cs *CloudService) addUser(ctx context.Context, clusterID, cloudClusterID string, user *helper.UserOption, env *store.CloudEnvironment) error {
	log.Printf("Running cloud AddUser for %s: %s", clusterID, cloudClusterID)

	var u databaseUserJSON
	if user == nil || user.Name == "" {
		u = newDatabaseUser(helper.RestUser, helper.RestPassCapella)
	} else {
		u = newDatabaseUser(user.Name, user.Password)
	}

	res, err := cs.client.DoInternal(ctx, "POST", fmt.Sprintf(createUserPath, env.TenantID, env.ProjectID, cloudClusterID), u, env)
	if err != nil {
		return err
	}
	defer res.Body.Close()

	// TODO: Use public API when AV-27634 fixed

	// res, err := cs.client.Do(ctx, "POST", fmt.Sprintf(createUserPath, cloudClusterID), u)
	// if err != nil {
	// 	return err
	// }
	// defer res.Body.Close()

	if res.StatusCode < 200 || res.StatusCode >= 300 {
		bb, err := ioutil.ReadAll(res.Body)
		if err != nil {
			return fmt.Errorf("create user failed: reason could not be determined: %v", err)
		}
		return fmt.Errorf("create user failed: %s", string(bb))
	}

	return nil
}

func (cs *CloudService) bucketHealth(ctx context.Context, clusterID, cloudClusterID, bucket string, env *store.CloudEnvironment) (string, error) {
	log.Printf("Running cloud bucket health for %s: %s", clusterID, cloudClusterID)

	res, err := cs.client.Do(ctx, "GET", fmt.Sprintf(clustersHealthPath, cloudClusterID), nil, env)
	if err != nil {
		return "", err
	}
	defer res.Body.Close()

	if res.StatusCode < 200 || res.StatusCode >= 300 {
		bb, err := ioutil.ReadAll(res.Body)
		if err != nil {
			return "", fmt.Errorf("bucket health failed: reason could not be determined: %v", err)
		}
		return "", fmt.Errorf("bucket health failed: %s", string(bb))
	}

	bb, err := ioutil.ReadAll(res.Body)
	if err != nil {
		return "", fmt.Errorf("bucket health succeeded: but body could not be read: %v", err)
	}

	var respBody clusterHealthResponse
	if err := json.Unmarshal(bb, &respBody); err != nil {
		return "", err
	}

	health, ok := respBody.BucketStats.HealthStats[bucket]
	if !ok {
		return "", fmt.Errorf("bucket not listed in health stats: %s", bucket)
	}

	return health, nil
}

func (cs *CloudService) GetCluster(ctx context.Context, clusterID string) (*cluster.Cluster, error) {
	if !cs.enabled {
		return nil, ErrCloudNotEnabled
	}

	_, env, err := cs.getCloudClusterEnv(ctx, clusterID)
	if err != nil {
		return nil, err
	}

	meta, err := cs.metaStore.GetClusterMeta(clusterID)
	if err != nil {
		log.Printf("Encountered unregistered cluster: %s", clusterID)
		return nil, err
	}

	if meta.CloudClusterID == "" {
		log.Printf("Encountered cluster with no cloud cluster ID: %s", clusterID)
		return nil, errors.New("unknown cluster")
	}

	log.Printf("Running cloud GetCluster for %s: %s", clusterID, meta.CloudClusterID)

	c, err := cs.getCluster(ctx, meta.CloudClusterID, env)
	if err != nil {
		return nil, err
	}

	res, err := cs.client.DoInternal(ctx, "GET", fmt.Sprintf(getNodesPath, env.TenantID, env.ProjectID, meta.CloudClusterID), nil, env)
	if err != nil {
		return nil, err
	}
	defer res.Body.Close()

	if res.StatusCode != 200 {
		bb, err := ioutil.ReadAll(res.Body)
		if err != nil {
			return nil, fmt.Errorf("get cluster failed: reason could not be determined: %v", err)
		}
		return nil, fmt.Errorf("get cluster failed: %s", string(bb))
	}

	bb, err := ioutil.ReadAll(res.Body)
	if err != nil {
		return nil, fmt.Errorf("get cluster succeeded: but body could not be read: %v", err)
	}

	var respBody getNodesJson
	if err := json.Unmarshal(bb, &respBody); err != nil {
		return nil, err
	}

	var nodes []*cluster.Node

	for _, nodeData := range respBody.Data {
		node := nodeData.Data
		nodes = append(nodes, &cluster.Node{
			ContainerID:          c.ID,
			Name:                 node.ID,
			InitialServerVersion: c.Version.Name,
			IPv4Address:          node.Hostname,
		})
	}

	return &cluster.Cluster{
		ID:         clusterID,
		Creator:    meta.Owner,
		Owner:      meta.Owner,
		Timeout:    meta.Timeout,
		Nodes:      nodes,
		EntryPoint: c.EndpointsSRV,
		Status:     c.Status,
	}, nil
}

func (cs *CloudService) AddUser(ctx context.Context, clusterID string, opts service.AddUserOptions, connCtx service.ConnectContext) error {
	if !cs.enabled {
		return ErrCloudNotEnabled
	}

	cloudClusterID, env, err := cs.getCloudClusterEnv(ctx, clusterID)
	if err != nil {
		return err
	}

	return cs.addUser(ctx, clusterID, cloudClusterID, opts.User, env)
}

func (cs *CloudService) AddIP(ctx context.Context, clusterID, ip string) error {
	if !cs.enabled {
		return ErrCloudNotEnabled
	}

	cloudClusterID, env, err := cs.getCloudClusterEnv(ctx, clusterID)
	if err != nil {
		return err
	}

	return cs.addIP(ctx, clusterID, cloudClusterID, ip, env)
}

// getAllClusters returns all clusters in the given environment
func (cs *CloudService) getAllClusters(ctx context.Context, env *store.CloudEnvironment) ([]*cluster.Cluster, error) {
	// TODO: Implement pagination
	// TODO: Support listing get all clusters across custom environments
	res, err := cs.client.Do(ctx, "GET", getAllClustersPath+fmt.Sprintf("?perPage=1000&projectId=%s", env.ProjectID), nil, env)
	if err != nil {
		return nil, err
	}
	defer res.Body.Close()

	if res.StatusCode != 200 {
		bb, err := ioutil.ReadAll(res.Body)
		if err != nil {
			return nil, fmt.Errorf("get all clusters failed: reason could not be determined: %v", err)
		}
		return nil, fmt.Errorf("get all clusters failed: %s", string(bb))
	}

	bb, err := ioutil.ReadAll(res.Body)
	if err != nil {
		return nil, fmt.Errorf("get all clusters succeeded: but body could not be read: %v", err)
	}

	var respBody getAllClustersJSON
	if err := json.Unmarshal(bb, &respBody); err != nil {
		return nil, err
	}

	var clusters []*cluster.Cluster
	for _, d := range respBody.Data.Items {
		c, err := cs.GetCluster(ctx, d.Name)
		if err != nil {
			log.Printf("Failed to get cluster: %s: %v", d.Name, err)
			continue
		}

		if !dyncontext.ContextIgnoreOwnership(ctx) && c.Owner != dyncontext.ContextUser(ctx) {
			continue
		}

		clusters = append(clusters, c)
	}

	return clusters, nil
}

// GetAllClusters returns all clusters in predefined environments
func (cs *CloudService) GetAllClusters(ctx context.Context) ([]*cluster.Cluster, error) {
	if !cs.enabled {
		return nil, ErrCloudNotEnabled
	}

	log.Printf("Running cloud GetAllClusters")

	var allClusters []*cluster.Cluster

	for _, env := range cs.envs {
		clusters, err := cs.getAllClusters(ctx, env)
		if err != nil {
			return nil, err
		}

		allClusters = append(allClusters, clusters...)
	}

	return allClusters, nil
}

func (cs *CloudService) KillCluster(ctx context.Context, clusterID string) error {
	if !cs.enabled {
		return ErrCloudNotEnabled
	}

	cloudClusterID, env, err := cs.getCloudClusterEnv(ctx, clusterID)
	if err != nil {
		return err
	}

	return cs.killCluster(ctx, clusterID, cloudClusterID, env)
}

func (cs *CloudService) KillAllClusters(ctx context.Context) error {
	if !cs.enabled {
		return ErrCloudNotEnabled
	}

	log.Printf("Running cloud KillAllClusters")

	clusters, err := cs.GetAllClusters(ctx)
	if err != nil {
		return err
	}

	var clustersToKill []string
	for _, c := range clusters {
		if c.Status != clusterDeleting {
			clustersToKill = append(clustersToKill, c.ID)
		}
	}

	signal := make(chan error)

	for _, clusterID := range clustersToKill {
		go func(clusterID string) {
			signal <- cs.KillCluster(ctx, clusterID)
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

func newDatabaseUser(username, password string) databaseUserJSON {
	return databaseUserJSON{
		Name:     username,
		Password: password,
	}
}

func generateCIDR() string {
	first := rand.Int() % 256
	second := (rand.Int() % 16) * 16
	return fmt.Sprintf("10.%d.%d.0/20", first, second)
}

func (cs *CloudService) postClusterCreate(ctx context.Context, clusterID, cloudClusterID string, env *store.CloudEnvironment, maxRequestTimeout time.Duration) error {
	tCtx, cancel := context.WithDeadline(ctx, time.Now().Add(25*time.Minute))
	defer cancel()

	for {
		getReqCtx, cancel := context.WithDeadline(tCtx, time.Now().Add(maxRequestTimeout))

		// If the tCtx deadline expires then this return an error.
		c, err := cs.getCluster(getReqCtx, cloudClusterID, env)
		cancel()
		if err != nil {
			return err
		}

		if c.Status == clusterHealthy {
			break
		}

		if c.Status == clusterDeploymentFailed {
			return errors.New("create cluster failed: status is deploymentFailed")
		}

		time.Sleep(5 * time.Second)
	}

	// Create default user
	defaultUser := &helper.UserOption{
		Name:     helper.RestUser,
		Password: helper.RestPassCapella,
	}
	if err := cs.addUser(ctx, clusterID, cloudClusterID, defaultUser, env); err != nil {
		return err
	}

	// allow all ips, these are only temporary, non security sensitive clusters so it's fine
	if err := cs.addIP(ctx, clusterID, cloudClusterID, "0.0.0.0/0", env); err != nil {
		return err
	}

	return nil
}

func (cs *CloudService) SetupCluster(ctx context.Context, clusterID string, opts ClusterSetupOptions,
	maxRequestTimeout time.Duration) error {
	if !cs.enabled {
		return ErrCloudNotEnabled
	}

	log.Printf("Running SetupCluster for %s with %v", clusterID, opts.Nodes)

	env := cs.defaultEnv

	if opts.EnvName != "" {
		customEnv, ok := cs.envs[opts.EnvName]
		if !ok {
			return fmt.Errorf("environment %s not found", opts.EnvName)
		}
		env = customEnv
	}

	if opts.Environment != nil {
		env = opts.Environment
	}

	provider := defaultProvider
	if opts.Provider != "" {
		switch opts.Provider {
		case "aws":
			provider = ProviderHostedAWS
		case "gcp":
			provider = ProviderHostedGCP
		default:
			return fmt.Errorf("provider %s is not supported", opts.Provider)
		}
	}

	region := opts.Region
	if region == "" {
		switch provider {
		case ProviderHostedAWS:
			region = defaultRegionAWS
		case ProviderHostedGCP:
			region = defaultRegionGCP
		}
	}

	singleAZ := defaultSingleAZ
	if opts.SingleAZ != nil {
		singleAZ = *opts.SingleAZ
	}

	var compute Instance
	switch provider {
	case ProviderHostedAWS:
		compute = defaultComputeAWS
	case ProviderHostedGCP:
		compute = defaultComputeGCP
	}

	var disk Disk
	switch provider {
	case ProviderHostedAWS:
		disk = defaultDiskAWS
	case ProviderHostedGCP:
		disk = defaultDiskeGCP
	}

	var specs []Spec
	for _, node := range opts.Nodes {
		services := []Service{}
		for _, service := range node.Services {
			services = append(services, Service{
				Type: service,
			})
		}
		specs = append(specs, Spec{
			Count:    node.Size,
			Services: services,
			Compute:  compute,
			Disk:     disk,
			DiskAutoScaling: DiskAutoScaling{
				//Now required for AWS and GCP. Not available for Azure yet
				Enabled: provider != ProviderAzure,
			},
		})
	}

	body := setupClusterJson{
		CIDR:      generateCIDR(),
		Name:      clusterID,
		ProjectID: env.ProjectID,
		Provider:  provider,
		Region:    region,
		SingleAZ:  singleAZ,
		Specs:     specs,
		Package:   defaultSupportPackage,
		Server:    opts.Server,
	}

	// Custom image
	if opts.Image != "" {
		serverVersion := serverVersionFromImageRegex.FindString(opts.Image)
		if serverVersion == "" {
			return fmt.Errorf("image %s does not contain a valid server version", opts.Image)
		}
		body.Override = &Override{
			Image:  opts.Image,
			Token:  env.OverrideToken,
			Server: serverVersion,
		}
	}

	reqCtx, cancel := context.WithDeadline(ctx, time.Now().Add(maxRequestTimeout))
	defer cancel()

	res, err := cs.client.DoInternal(reqCtx, "POST", fmt.Sprintf(createClusterPath, env.TenantID), body, env)
	if err != nil {
		return err
	}
	defer res.Body.Close()

	if res.StatusCode < 200 || res.StatusCode >= 300 {
		bb, err := ioutil.ReadAll(res.Body)
		if err != nil {
			return fmt.Errorf("create cluster failed: reason could not be determined: %v", err)
		}
		errorBody := string(bb)
		// retry if the CIDR is already in use
		// TODO: Is there a way we can prevent this?
		if strings.Contains(errorBody, "ErrClusterInvalidCIDRNotUnique") {
			return cs.SetupCluster(ctx, clusterID, opts, maxRequestTimeout)
		}
		return fmt.Errorf("create cluster failed: %d: %s", res.StatusCode, string(bb))
	}

	type ID struct {
		ID string `json:"id"`
	}

	b, err := ioutil.ReadAll(res.Body)
	if err != nil {
		return err
	}
	id := &ID{}
	err = json.Unmarshal(b, id)
	if err != nil {
		return err
	}

	cloudClusterID := id.ID

	err = cs.metaStore.UpdateClusterMeta(clusterID, func(meta store.ClusterMeta) (store.ClusterMeta, error) {
		meta.CloudClusterID = cloudClusterID
		return meta, nil
	})
	if err != nil {
		return err
	}

	err = cs.postClusterCreate(ctx, clusterID, cloudClusterID, env, maxRequestTimeout)
	if err != nil {
		go func() {
			cs.killCluster(ctx, clusterID, cloudClusterID, env)
		}()
		return err
	}

	return nil
}

func (cs *CloudService) AddBucket(ctx context.Context, clusterID string, opts service.AddBucketOptions, connCtx service.ConnectContext) error {
	if !cs.enabled {
		return ErrCloudNotEnabled
	}

	cloudClusterID, env, err := cs.getCloudClusterEnv(ctx, clusterID)
	if err != nil {
		return err
	}

	return cs.addBucket(ctx, clusterID, cloudClusterID, opts, env)
}

func (cs *CloudService) AddCollection(ctx context.Context, clusterID string, opts service.AddCollectionOptions, connCtx service.ConnectContext) error {
	if !cs.enabled {
		return ErrCloudNotEnabled
	}
	connCtx.RestPassword = helper.RestPassCapella
	return common.AddCollection(ctx, cs, clusterID, opts, connCtx)
}

func (cs *CloudService) SetupCertAuth(ctx context.Context, clusterID string, opts service.SetupClientCertAuthOptions, connCtx service.ConnectContext) (*service.CertAuthResult, error) {
	if !cs.enabled {
		return nil, ErrCloudNotEnabled
	}
	return nil, errors.New("unsupported operation")
}

func (cs *CloudService) addSampleBucket(ctx context.Context, clusterID, cloudClusterID, name string, connCtx service.ConnectContext, env *store.CloudEnvironment) error {
	log.Printf("Running cloud AddSampleBucket for %s: %s", clusterID, cloudClusterID)

	body := addSampleBucketJSON{
		Name: name,
	}

	res, err := cs.client.DoInternal(ctx, "POST", fmt.Sprintf(addSampleBucketPath, env.TenantID, env.ProjectID, cloudClusterID), body, env)
	if err != nil {
		return err
	}
	defer res.Body.Close()

	if res.StatusCode < 200 || res.StatusCode >= 300 {
		bb, err := ioutil.ReadAll(res.Body)
		if err != nil {
			return fmt.Errorf("add sample bucket failed: reason could not be determined: %v", err)
		}
		return fmt.Errorf("add sample bucket failed: %s", string(bb))
	}

	c, err := cs.GetCluster(ctx, clusterID)
	if err != nil {
		return err
	}

	node := common.NewNode(c.Nodes[0].IPv4Address, c.Nodes[0].InitialServerVersion, connCtx)

	if err = node.WaitForBucketHealthy(name); err != nil {
		return err
	}

	return node.PollSampleBucket(name)
}

func (cs *CloudService) AddSampleBucket(ctx context.Context, clusterID string, opts service.AddSampleOptions, connCtx service.ConnectContext) error {
	if !cs.enabled {
		return ErrCloudNotEnabled
	}

	cloudClusterID, env, err := cs.getCloudClusterEnv(ctx, clusterID)
	if err != nil {
		return err
	}

	connCtx.RestPassword = helper.RestPassCapella

	return cs.addSampleBucket(ctx, clusterID, cloudClusterID, opts.SampleBucket, connCtx, env)
}

func (cs *CloudService) SetupClusterEncryption(ctx context.Context, clusterID string, opts service.SetupClusterEncryptionOptions, connCtx service.ConnectContext) error {
	if !cs.enabled {
		return ErrCloudNotEnabled
	}
	return errors.New("unsupported operation")
}

func (cs *CloudService) ConnString(ctx context.Context, clusterID string, useSSL, useSrv bool) (string, error) {
	if !useSSL {
		return "", errors.New("only SSL supported for cloud")
	}

	c, err := cs.GetCluster(ctx, clusterID)
	if err != nil {
		return "", err
	}

	return "couchbases://" + c.EntryPoint, nil
}

func (cs *CloudService) getCloudClusterEnv(ctx context.Context, clusterID string) (string, *store.CloudEnvironment, error) {
	meta, err := cs.metaStore.GetClusterMeta(clusterID)
	if err != nil {
		log.Printf("Encountered unregistered cluster: %s", clusterID)
		return "", nil, err
	}

	if meta.CloudClusterID == "" {
		log.Printf("Encountered cluster with no cloud cluster ID: %s", clusterID)
		return "", nil, errors.New("unknown cluster")
	}

	env := cs.defaultEnv

	if meta.CloudEnvName != "" {
		customEnv, ok := cs.envs[meta.CloudEnvName]
		if !ok {
			return "", nil, fmt.Errorf("unknown cloud environment: %s", meta.CloudEnvName)
		}
		env = customEnv
	}

	if meta.CloudEnvironment != nil {
		env = meta.CloudEnvironment
	}

	return meta.CloudClusterID, env, nil
}
