package ec2

import (
	"context"
	"errors"
	"fmt"
	"log"
	"time"

	"github.com/aws/aws-sdk-go-v2/aws"
	"github.com/aws/aws-sdk-go-v2/config"
	"github.com/aws/aws-sdk-go-v2/service/ec2"
	"github.com/aws/aws-sdk-go-v2/service/ec2/types"
	"github.com/couchbaselabs/cbdynclusterd/cluster"
	"github.com/couchbaselabs/cbdynclusterd/dyncontext"
	"github.com/couchbaselabs/cbdynclusterd/helper"
	"github.com/couchbaselabs/cbdynclusterd/service"
	"github.com/couchbaselabs/cbdynclusterd/service/common"
	"github.com/couchbaselabs/cbdynclusterd/store"
)

var (
	ErrEC2NotEnabled = errors.New("ec2 is not enabled, credentials not set")
)

type EC2Service struct {
	enabled          bool
	metaStore        *store.ReadOnlyMetaDataStore
	client           *ec2.Client
	aliasRepoPath    string
	securityGroup    string
	keyName          string
	downloadPassword string
}

func NewEC2Service(aliasRepoPath, securityGroup, keyName, downloadPassword string, metaStore *store.ReadOnlyMetaDataStore) *EC2Service {
	enabled := true
	client := &ec2.Client{}
	cfg, err := config.LoadDefaultConfig(context.TODO())
	if err != nil {
		enabled = false
	} else {
		client = ec2.NewFromConfig(cfg)
	}
	enabled = enabled && securityGroup != "" && keyName != "" && downloadPassword != ""
	log.Printf("EC2 enabled: %t", enabled)
	return &EC2Service{
		enabled:          enabled,
		metaStore:        metaStore,
		client:           client,
		aliasRepoPath:    aliasRepoPath,
		keyName:          keyName,
		securityGroup:    securityGroup,
		downloadPassword: downloadPassword,
	}
}

func (s *EC2Service) AllocateCluster(ctx context.Context, opts service.AllocateClusterOptions) (string, error) {
	if !s.enabled {
		return "", ErrEC2NotEnabled
	}

	log.Printf("Allocating cluster (requested by: %s)", dyncontext.ContextUser(ctx))

	if len(opts.Nodes) == 0 {
		return "", errors.New("must specify at least a single node for the cluster")
	}
	if len(opts.Nodes) > 10 {
		return "", errors.New("cannot allocate clusters with more than 10 nodes")
	}

	if err := common.GetConfigRepo(s.aliasRepoPath); err != nil {
		log.Printf("Get config failed: %v", err)
		return "", err
	}

	clusterID := helper.NewRandomClusterID()

	nodesToAllocate, err := common.CreateNodesToAllocate(opts.Nodes, s.aliasRepoPath)

	if err != nil {
		return "", err
	}

	if len(nodesToAllocate) > 0 {
		// We assume that all nodes are using the same server version.
		node := nodesToAllocate[0]

		err := s.ensureImageExists(ctx, node.VersionInfo, clusterID)
		if err != nil {
			return "", err
		}
	}

	signal := make(chan error)

	for _, node := range nodesToAllocate {
		go func(clusterID string, node common.NodeOptions) {
			_, err := s.allocateNode(ctx, clusterID, opts.Deadline, node)
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
		s.KillCluster(ctx, clusterID)
		return "", createError
	}

	return clusterID, nil
}

func (s *EC2Service) ensureImageExists(ctx context.Context, nodeVersion *common.NodeVersion, clusterID string) error {

	imageName := nodeVersion.ToImageName("cbdyncluster")

	out, err := s.client.DescribeImages(ctx, &ec2.DescribeImagesInput{
		Filters: []types.Filter{
			{
				Name:   aws.String("name"),
				Values: []string{(imageName)},
			},
		},
	})

	if err != nil {
		return err
	}

	if len(out.Images) == 1 {
		return nil
	}

	log.Printf("No image found for %s, building...", imageName)

	err = CallPacker(PackerOptions{
		DownloadPassword: s.downloadPassword,
		Version:          nodeVersion.Version,
		BuildPkg:         nodeVersion.ToPkgName(),
		BaseUrl:          nodeVersion.ToExternalURL(),
		AmiName:          imageName,
		Arch:             nodeVersion.Arch,
		OS:               nodeVersion.OS,
	})

	return err
}

func (s *EC2Service) allocateNode(ctx context.Context, clusterID string, timeout time.Time, opts common.NodeOptions) (string, error) {
	log.Printf("Allocating node for cluster %s (requested by: %s)", clusterID, dyncontext.ContextUser(ctx))

	imageName := opts.VersionInfo.ToImageName("cbdyncluster")
	instanceName := fmt.Sprintf("dynclsr-%s-%s", clusterID, opts.Name)

	out, err := s.client.DescribeImages(ctx, &ec2.DescribeImagesInput{
		Filters: []types.Filter{
			{
				Name:   aws.String("name"),
				Values: []string{(imageName)},
			},
		},
	})

	if err != nil {
		return "", err
	}

	if len(out.Images) != 1 {
		return "", errors.New("no image found")
	}

	ami := out.Images[0].ImageId

	createdInstances, err := s.client.RunInstances(ctx, &ec2.RunInstancesInput{
		MaxCount:         aws.Int32(1),
		MinCount:         aws.Int32(1),
		ImageId:          ami,
		InstanceType:     types.InstanceTypeT4gXlarge,
		KeyName:          aws.String(s.keyName),
		SecurityGroupIds: []string{*aws.String(s.securityGroup)},
		TagSpecifications: []types.TagSpecification{
			{
				ResourceType: "instance",
				Tags: []types.Tag{{
					Key:   aws.String("Name"),
					Value: aws.String(instanceName),
				}, {
					Key:   aws.String("com.couchbase.dyncluster.cluster_id"),
					Value: aws.String(clusterID),
				}, {
					Key:   aws.String("com.couchbase.dyncluster.creator"),
					Value: aws.String(dyncontext.ContextUser(ctx)),
				}, {
					Key:   aws.String("com.couchbase.dyncluster.node_name"),
					Value: aws.String(opts.Name),
				}, {
					Key:   aws.String("com.couchbase.dyncluster.initial_server_version"),
					Value: aws.String(opts.ServerVersion),
				}},
			},
		},
	})

	if err != nil {
		return "", err
	}

	instanceId := *createdInstances.Instances[0].InstanceId

	err = ec2.NewInstanceRunningWaiter(s.client).Wait(ctx, &ec2.DescribeInstancesInput{
		InstanceIds: []string{instanceId},
	}, 120*time.Second)

	if err != nil {
		return "", err
	}

	return instanceId, nil
}

func (s *EC2Service) getFilteredClusters(ctx context.Context, filters []types.Filter) ([]*cluster.Cluster, error) {
	out, err := s.client.DescribeInstances(ctx, &ec2.DescribeInstancesInput{
		Filters: filters,
	})
	if err != nil {
		return nil, err
	}

	clusterMap := make(map[string][]types.Instance)

	for _, reservation := range out.Reservations {
		for _, instance := range reservation.Instances {
			if instance.State.Name != types.InstanceStateNameRunning || instance.PublicDnsName == nil {
				continue
			}
			clusterID := ""
			for _, tag := range instance.Tags {
				if *tag.Key == "com.couchbase.dyncluster.cluster_id" {
					clusterID = *tag.Value
					clusterMap[clusterID] = append(clusterMap[clusterID], instance)
				}
			}

		}
	}

	var clusters []*cluster.Cluster
	for clusterID, instances := range clusterMap {
		meta, err := s.metaStore.GetClusterMeta(clusterID)
		if err != nil {
			log.Printf("Encountered unregistered cluster: %s", clusterID)
			continue
		}

		clusterCreator := ""

		var nodes []*cluster.Node
		for _, instance := range instances {

			tags := make(map[string]string)

			for _, tag := range instance.Tags {
				tags[*tag.Key] = *tag.Value
			}

			instanceCreator := tags["com.couchbase.dyncluster.creator"]
			if clusterCreator == "" {
				clusterCreator = instanceCreator
			}

			nodes = append(nodes, &cluster.Node{
				ContainerID:          *instance.InstanceId,
				ContainerName:        tags["Name"],
				State:                string(instance.State.Name),
				Name:                 tags["com.couchbase.dyncluster.node_name"],
				InitialServerVersion: tags["com.couchbase.dyncluster.initial_server_version"],
				IPv4Address:          *instance.PublicDnsName,
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

func (s *EC2Service) GetAllClusters(ctx context.Context) ([]*cluster.Cluster, error) {
	if !s.enabled {
		return nil, ErrEC2NotEnabled
	}

	log.Printf("Running ec2 GetAllClusters (requested by: %s)", dyncontext.ContextUser(ctx))

	filters := []types.Filter{
		{Name: aws.String("tag-key"), Values: []string{"com.couchbase.dyncluster.cluster_id"}},
	}

	return s.getFilteredClusters(ctx, filters)
}

func (s *EC2Service) AddUser(ctx context.Context, clusterID string, user *helper.UserOption, bucket string) error {
	return errors.New("not supported")
}

func (s *EC2Service) AddIP(ctx context.Context, clusterID, ip string) error {
	return errors.New("not supported")
}

func (s *EC2Service) GetCluster(ctx context.Context, clusterID string) (*cluster.Cluster, error) {
	if !s.enabled {
		return nil, ErrEC2NotEnabled
	}

	log.Printf("Running ec2 GetCluster (requested by: %s)", dyncontext.ContextUser(ctx))

	filters := []types.Filter{
		{Name: aws.String("tag:com.couchbase.dyncluster.cluster_id"), Values: []string{clusterID}},
	}

	clusters, err := s.getFilteredClusters(ctx, filters)
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

func (s *EC2Service) KillCluster(ctx context.Context, clusterID string) error {
	if !s.enabled {
		return ErrEC2NotEnabled
	}

	log.Printf("Killing ec2 cluster %s (requested by: %s)", clusterID, dyncontext.ContextUser(ctx))

	c, err := s.GetCluster(ctx, clusterID)
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
			signal <- s.terminateInstance(ctx, nodeID)
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

func (s *EC2Service) KillAllClusters(ctx context.Context) error {
	log.Printf("Killing all ec2 clusters")
	return common.KillAllClusters(ctx, s)
}

func (s *EC2Service) AddCollection(ctx context.Context, clusterID string, opts service.AddCollectionOptions) error {
	return common.AddCollection(ctx, s, clusterID, opts)
}

func (s *EC2Service) SetupCertAuth(ctx context.Context, clusterID string, opts service.SetupClientCertAuthOptions) (*service.CertAuthResult, error) {
	return nil, errors.New("not supported yet, requires SSH access")
}

func (s *EC2Service) AddBucket(ctx context.Context, clusterID string, opts service.AddBucketOptions) error {
	return common.AddBucket(ctx, s, clusterID, opts)
}

func (s *EC2Service) AddSampleBucket(ctx context.Context, clusterID string, opts service.AddSampleOptions) error {
	return common.AddSampleBucket(ctx, s, clusterID, opts)
}

func (s *EC2Service) ConnString(ctx context.Context, clusterID string, useSSL bool) (string, error) {
	return common.ConnString(ctx, s, clusterID, useSSL)
}

func (s *EC2Service) terminateInstance(ctx context.Context, instanceId string) error {
	_, err := s.client.TerminateInstances(ctx, &ec2.TerminateInstancesInput{
		InstanceIds: []string{instanceId},
	})

	return err
}
