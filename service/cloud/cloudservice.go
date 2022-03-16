package cloud

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"io/ioutil"
	"log"
	"math/rand"
	"net"
	"strings"
	"time"

	"github.com/couchbaselabs/cbdynclusterd/cluster"
	"github.com/couchbaselabs/cbdynclusterd/dyncontext"
	"github.com/couchbaselabs/cbdynclusterd/helper"
	"github.com/couchbaselabs/cbdynclusterd/service"
	"github.com/couchbaselabs/cbdynclusterd/store"
)

type CloudService struct {
	projectID string
	enabled   bool
	client    *client
	metaStore *store.ReadOnlyMetaDataStore
}

func NewCloudService(accessKey, privateKey, projectID, baseURL string, metaStore *store.ReadOnlyMetaDataStore) *CloudService {
	log.Printf("Cloud enabled: %t", projectID != "")
	return &CloudService{
		enabled:   projectID != "",
		projectID: projectID,
		client:    NewClient(baseURL, accessKey, privateKey),
		metaStore: metaStore,
	}
}

func (cs *CloudService) getCluster(ctx context.Context, cloudClusterID string) (*getClusterJSON, error) {
	res, err := cs.client.Do(ctx, "GET", getClusterPath+cloudClusterID, nil)
	if err != nil {
		return nil, err
	}

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

func (cs *CloudService) addBucket(ctx context.Context, clusterID, cloudClusterID string, opts service.AddBucketOptions) error {
	return errors.New("unsupported operation")
	// log.Printf("Running cloud CreateBucket for %s: %s", clusterID, cloudClusterID)

	// body := bucketSpecJSON{
	// 	Name:        opts.Name,
	// 	MemoryQuota: opts.RamQuota,
	// 	Replicas:    opts.ReplicaCount,
	// }

	// res, err := cs.client.Do(ctx, "POST", fmt.Sprintf(createBucketPath, cloudClusterID), body)
	// if err != nil {
	// 	return err
	// }

	// if res.StatusCode < 200 || res.StatusCode >= 300 {
	// 	bb, err := ioutil.ReadAll(res.Body)
	// 	if err != nil {
	// 		return fmt.Errorf("create bucket failed: reason could not be determined: %v", err)
	// 	}
	// 	return fmt.Errorf("create bucket failed: %s", string(bb))
	// }

	// return nil
}

func (cs *CloudService) addIP(ctx context.Context, clusterID, cloudClusterID, ip string) error {
	return errors.New("unsupported operation")
	// log.Printf("Running cloud AddIP for %s: %s", clusterID, cloudClusterID)

	// body := allowListJSON{
	// 	CIDR:     ip,
	// 	RuleType: "permanent",
	// }

	// res, err := cs.client.Do(ctx, "POST", fmt.Sprintf(addIPPath, cloudClusterID), body)
	// if err != nil {
	// 	return err
	// }

	// if res.StatusCode < 200 || res.StatusCode >= 300 {
	// 	bb, err := ioutil.ReadAll(res.Body)
	// 	if err != nil {
	// 		return fmt.Errorf("add ip failed: reason could not be determined: %v", err)
	// 	}
	// 	return fmt.Errorf("add ip failed: %s", string(bb))
	// }

	// return nil
}

func (cs *CloudService) killCluster(ctx context.Context, clusterID, cloudClusterID string) error {
	log.Printf("Running cloud KillCluster for %s: %s", clusterID, cloudClusterID)

	res, err := cs.client.Do(ctx, "DELETE", deleteClusterPath+cloudClusterID, nil)
	if err != nil {
		return err
	}

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

func (cs *CloudService) addUser(ctx context.Context, clusterID, cloudClusterID, bucket string, user *helper.UserOption) error {
	log.Printf("Running cloud AddUser for %s: %s", clusterID, cloudClusterID)

	var u databaseUserJSON
	if user == nil || user.Name == "" {
		u = newDatabaseUser("Administrator", "Pa$$w0rd")
	} else {
		u = newDatabaseUser(user.Name, user.Password)
	}

	res, err := cs.client.Do(ctx, "POST", fmt.Sprintf(createUserPath, cloudClusterID), u)
	if err != nil {
		return err
	}

	if res.StatusCode < 200 || res.StatusCode >= 300 {
		bb, err := ioutil.ReadAll(res.Body)
		if err != nil {
			return fmt.Errorf("create user failed: reason could not be determined: %v", err)
		}
		return fmt.Errorf("create user failed: %s", string(bb))
	}

	return nil
}

func (cs *CloudService) deleteDefaultCloudBucket(ctx context.Context, clusterID, cloudClusterID string) error {
	return errors.New("unsupported operation")
	// log.Printf("Running cloud delete couchbasecloudbucket bucket for %s: %s", clusterID, cloudClusterID)

	// res, err := cs.client.Do(ctx, "DELETE", fmt.Sprintf(deleteBucketPath, cloudClusterID), bucketDeleteJSON{
	// 	Name: "couchbasecloudbucket",
	// })
	// if err != nil {
	// 	return err
	// }

	// if res.StatusCode < 200 || res.StatusCode >= 300 {
	// 	bb, err := ioutil.ReadAll(res.Body)
	// 	if err != nil {
	// 		return fmt.Errorf("delete bucket failed: reason could not be determined: %v", err)
	// 	}
	// 	return fmt.Errorf("delete bucket failed: %s", string(bb))
	// }

	// return nil
}

func (cs *CloudService) bucketHealth(ctx context.Context, clusterID, cloudClusterID, bucket string) (string, error) {
	log.Printf("Running cloud bucket health for %s: %s", clusterID, cloudClusterID)

	res, err := cs.client.Do(ctx, "GET", fmt.Sprintf(clustersHealthPath, cloudClusterID), nil)
	if err != nil {
		return "", err
	}

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

	c, err := cs.getCluster(ctx, meta.CloudClusterID)
	if err != nil {
		return nil, err
	}

	var nodes []*cluster.Node

	_, addrs, err := net.LookupSRV("couchbases", "tcp", c.EndpointsSRV)

	if err != nil {
		for i, addr := range addrs {
			nodes = append(nodes, &cluster.Node{
				ContainerID:          c.ID,
				Name:                 fmt.Sprintf("node_%d", i),
				InitialServerVersion: c.Version.Name,
				IPv4Address:          addr.Target[:len(addr.Target)-1],
			})
		}
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

func (cs *CloudService) AddUser(ctx context.Context, clusterID string, user *helper.UserOption, bucket string) error {
	if !cs.enabled {
		return ErrCloudNotEnabled
	}

	meta, err := cs.metaStore.GetClusterMeta(clusterID)
	if err != nil {
		log.Printf("Encountered unregistered cluster: %s", clusterID)
		return err
	}

	if meta.CloudClusterID == "" {
		log.Printf("Encountered cluster with no cloud cluster ID: %s", clusterID)
		return errors.New("unknown cluster")
	}

	return cs.addUser(ctx, clusterID, meta.CloudClusterID, bucket, user)
}

type allowListJSON struct {
	CIDR     string `json:"cidrBlock"`
	RuleType string `json:"ruleType"`
}

func (cs *CloudService) AddIP(ctx context.Context, clusterID, ip string) error {
	if !cs.enabled {
		return ErrCloudNotEnabled
	}

	meta, err := cs.metaStore.GetClusterMeta(clusterID)
	if err != nil {
		log.Printf("Encountered unregistered cluster: %s", clusterID)
		return err
	}

	if meta.CloudClusterID == "" {
		log.Printf("Encountered cluster with no cloud cluster ID: %s", clusterID)
		return errors.New("unknown cluster")
	}

	return cs.addIP(ctx, clusterID, meta.CloudClusterID, ip)
}

func (cs *CloudService) GetAllClusters(ctx context.Context) ([]*cluster.Cluster, error) {
	if !cs.enabled {
		return nil, ErrCloudNotEnabled
	}

	log.Printf("Running cloud GetAllClusters")

	// TODO: Implement pagination
	res, err := cs.client.Do(ctx, "GET", getAllClustersPath+fmt.Sprintf("?perPage=1000&projectId=%s", cs.projectID), nil)
	if err != nil {
		return nil, err
	}

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

func (cs *CloudService) KillCluster(ctx context.Context, clusterID string) error {
	if !cs.enabled {
		return ErrCloudNotEnabled
	}

	meta, err := cs.metaStore.GetClusterMeta(clusterID)
	if err != nil {
		log.Printf("Encountered unregistered cluster: %s", clusterID)
		return err
	}

	if meta.CloudClusterID == "" {
		log.Printf("Encountered cluster with no cloud cluster ID: %s", clusterID)
		return errors.New("unknown cluster")
	}

	return cs.killCluster(ctx, clusterID, meta.CloudClusterID)
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
		Username:         username,
		Password:         password,
		AllBucketsAccess: V3BucketRoleDataWriter,
	}
}

func generateCIDR() string {
	first := rand.Int() % 256
	second := (rand.Int() % 16) * 16
	return fmt.Sprintf("10.%d.%d.0/20", first, second)
}

func (cs *CloudService) SetupCluster(ctx context.Context, clusterID string, opts ClusterSetupOptions,
	maxRequestTimeout time.Duration) (string, error) {
	if !cs.enabled {
		return "", ErrCloudNotEnabled
	}

	log.Printf("Running SetupCluster for %s with %v", clusterID, opts.Nodes)

	var servers []V3Server
	for _, node := range opts.Nodes {
		servers = append(servers, V3Server{
			Size:     node.Size,
			Compute:  defaultCompute,
			Services: node.Services,
			Storage:  defaultStorage,
		})
	}

	body := setupClusterJson{
		Environment: V3EnvironmentHosted,
		Name:        clusterID,
		ProjectID:   cs.projectID,
		Place: V3Place{
			SingleAZ: true,
			Hosted: V3PlaceHosted{
				Provider: V3ProviderAWS,
				Region:   defaultRegion,
				CIDR:     generateCIDR(),
			},
		},
		Servers:        servers,
		SupportPackage: defaultSupportPackage,
	}

	reqCtx, cancel := context.WithDeadline(ctx, time.Now().Add(maxRequestTimeout))
	defer cancel()

	res, err := cs.client.Do(reqCtx, "POST", createClusterPath, body)
	if err != nil {
		return "", err
	}

	if res.StatusCode < 200 || res.StatusCode >= 300 {
		bb, err := ioutil.ReadAll(res.Body)
		if err != nil {
			return "", fmt.Errorf("create cluster failed: reason could not be determined: %v", err)
		}
		errorBody := string(bb)
		// retry if the CIDR is already in use
		// TODO: Is there a way we can prevent this?
		if strings.Contains(errorBody, "ErrClusterInvalidCIDRNotUnique") {
			return cs.SetupCluster(ctx, clusterID, opts, maxRequestTimeout)
		}
		return "", fmt.Errorf("create cluster failed: %d: %s", res.StatusCode, string(bb))
	}

	location := res.Header.Get("Location")
	location = strings.TrimPrefix(location, createClusterPath+"/")

	tCtx, cancel := context.WithDeadline(ctx, time.Now().Add(25*time.Minute))
	defer cancel()

	for {
		getReqCtx, cancel := context.WithDeadline(tCtx, time.Now().Add(maxRequestTimeout))

		// If the tCtx deadline expires then this return an error.
		c, err := cs.getCluster(getReqCtx, location)
		cancel()
		if err != nil {
			go func() {
				cs.killCluster(ctx, clusterID, location)
			}()
			return "", err
		}

		if c.Status == clusterHealthy {
			break
		}

		if c.Status == clusterDeploymentFailed {
			return "", errors.New("create cluster failed: status is deploymentFailed")
		}

		time.Sleep(5 * time.Second)
	}

	// TODO: Return root certificate when API is supported so we can securely connect to the cluster

	return location, nil
}

func (cs *CloudService) AddBucket(ctx context.Context, clusterID string, opts service.AddBucketOptions) error {
	if !cs.enabled {
		return ErrCloudNotEnabled
	}
	return errors.New("unsupported operation")
	// meta, err := cs.metaStore.GetClusterMeta(clusterID)
	// if err != nil {
	// 	log.Printf("Encountered unregistered cluster: %s", clusterID)
	// 	return err
	// }

	// if meta.CloudClusterID == "" {
	// 	log.Printf("Encountered cluster with no cloud cluster ID: %s", clusterID)
	// 	return errors.New("unknown cluster")
	// }

	// return cs.addBucket(ctx, clusterID, meta.CloudClusterID, opts)
}

func (cs *CloudService) AddCollection(ctx context.Context, clusterID string, opts service.AddCollectionOptions) error {
	if !cs.enabled {
		return ErrCloudNotEnabled
	}
	return errors.New("unsupported operation")
}

func (cs *CloudService) SetupCertAuth(ctx context.Context, clusterID string, opts service.SetupClientCertAuthOptions) (*service.CertAuthResult, error) {
	if !cs.enabled {
		return nil, ErrCloudNotEnabled
	}
	return nil, errors.New("unsupported operation")
}

func (cs *CloudService) AddSampleBucket(ctx context.Context, clusterID string, opts service.AddSampleOptions) error {
	if !cs.enabled {
		return ErrCloudNotEnabled
	}
	return errors.New("unsupported operation")
}

func (cs *CloudService) SetupClusterEncryption(ctx context.Context, clusterID string, opts service.SetupClusterEncryptionOptions) error {
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
