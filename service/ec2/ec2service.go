package ec2

import (
	"context"
	"errors"
	"fmt"
	"log"
	"sync"
	"time"

	"github.com/aws/aws-sdk-go-v2/aws"
	"github.com/aws/aws-sdk-go-v2/aws/retry"
	"github.com/aws/aws-sdk-go-v2/config"
	"github.com/aws/aws-sdk-go-v2/service/ec2"
	"github.com/aws/aws-sdk-go-v2/service/ec2/types"
	"github.com/aws/aws-sdk-go-v2/service/route53"
	route53types "github.com/aws/aws-sdk-go-v2/service/route53/types"
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
	route53Enabled   bool
	metaStore        *store.ReadOnlyMetaDataStore
	client           *ec2.Client
	route53Client    *route53.Client
	aliasRepoPath    string
	securityGroup    string
	keyName          string
	keyPath          string
	downloadPassword string
	domainName       string
	hostedZoneId     string

	buildingImages map[string]chan error
	mu             sync.Mutex
}

type EC2ServiceOptions struct {
	AliasRepoPath    string
	SecurityGroup    string
	KeyName          string
	KeyPath          string
	DownloadPassword string
	MetaStore        *store.ReadOnlyMetaDataStore
	DomainName       string
	HostedZoneId     string
}

func NewEC2Service(opts *EC2ServiceOptions) *EC2Service {
	enabled := true
	client := &ec2.Client{}
	route53Client := &route53.Client{}
	cfg, err := config.LoadDefaultConfig(context.TODO(), config.WithRetryer(func() aws.Retryer {
		return retry.AddWithMaxAttempts(retry.NewStandard(), 0) // keep retrying requests if the error is retryable
	}))
	if err != nil {
		enabled = false
	} else {
		client = ec2.NewFromConfig(cfg)
		route53Client = route53.NewFromConfig(cfg)
	}
	enabled = enabled && opts.SecurityGroup != "" && opts.KeyName != "" && opts.DownloadPassword != ""
	route53Enabled := opts.DomainName != "" && opts.HostedZoneId != ""
	log.Printf("EC2 enabled: %t", enabled)
	log.Printf("Route53 enabled: %t", route53Enabled)

	return &EC2Service{
		enabled:          enabled,
		route53Enabled:   route53Enabled,
		metaStore:        opts.MetaStore,
		client:           client,
		aliasRepoPath:    opts.AliasRepoPath,
		keyName:          opts.KeyName,
		keyPath:          opts.KeyPath,
		securityGroup:    opts.SecurityGroup,
		downloadPassword: opts.DownloadPassword,
		route53Client:    route53Client,
		hostedZoneId:     opts.HostedZoneId,
		domainName:       opts.DomainName,

		buildingImages: make(map[string]chan error),
	}
}

func (s *EC2Service) AllocateCluster(ctx context.Context, opts service.AllocateClusterOptions) error {
	if !s.enabled {
		return ErrEC2NotEnabled
	}

	log.Printf("Allocating cluster (requested by: %s)", dyncontext.ContextUser(ctx))

	if len(opts.Nodes) == 0 {
		return errors.New("must specify at least a single node for the cluster")
	}
	if len(opts.Nodes) > 10 {
		return errors.New("cannot allocate clusters with more than 10 nodes")
	}

	if err := common.GetConfigRepo(s.aliasRepoPath); err != nil {
		log.Printf("Get config failed: %v", err)
		return err
	}

	nodesToAllocate, err := common.CreateNodesToAllocate(opts.Nodes, s.aliasRepoPath)

	if err != nil {
		return err
	}

	if len(nodesToAllocate) > 0 {
		// We assume that all nodes are using the same server version.
		node := nodesToAllocate[0]

		err := s.ensureImageExists(ctx, node.VersionInfo, opts.ClusterID)
		if err != nil {
			return err
		}
	}

	_, err = s.allocateNodes(ctx, opts.ClusterID, nodesToAllocate)

	if err != nil {
		s.KillCluster(ctx, opts.ClusterID)
		return err
	}

	return nil
}

func (s *EC2Service) ensureImageExists(ctx context.Context, nodeVersion *common.NodeVersion, clusterID string) error {

	imageName := nodeVersion.ToImageName("cbdyncluster")

	out, err := s.client.DescribeImages(ctx, &ec2.DescribeImagesInput{
		Filters: []types.Filter{
			{
				Name:   aws.String("name"),
				Values: []string{(imageName)},
			},
			{
				Name:   aws.String("state"),
				Values: []string{"available"},
			},
		},
	})

	if err != nil {
		return err
	}

	if len(out.Images) == 1 {
		return nil
	}

	s.mu.Lock()
	// wait for other build to complete
	if waitChan, building := s.buildingImages[imageName]; building {
		s.mu.Unlock()
		log.Printf("Image %s is already being built, waiting...", imageName)
		select {
		case err := <-waitChan:
			return err
		case <-time.After(1 * time.Hour):
			return errors.New("timed out waiting for image to be built")
		}
	}
	waitChan := make(chan error)
	s.buildingImages[imageName] = waitChan
	s.mu.Unlock()

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

	// inform any waiters
	waitChan <- err
	close(waitChan)
	s.mu.Lock()
	delete(s.buildingImages, imageName)
	s.mu.Unlock()

	return err
}

func (s *EC2Service) removeSrvRecord(ctx context.Context, cluster *cluster.Cluster) error {
	return s.changeSrvRecord(ctx, cluster, route53types.ChangeActionDelete)
}

func (s *EC2Service) createSrvRecord(ctx context.Context, cluster *cluster.Cluster) error {
	return s.changeSrvRecord(ctx, cluster, route53types.ChangeActionCreate)
}

func (s *EC2Service) changeSrvRecord(ctx context.Context, cluster *cluster.Cluster, action route53types.ChangeAction) error {
	hostnames := make([]string, 0, len(cluster.Nodes))
	for _, node := range cluster.Nodes {
		hostnames = append(hostnames, node.IPv4Address)
	}

	changes := make([]route53types.Change, 0, 2)

	type variant struct {
		port int
		name string
	}

	// secure and insecure
	variants := []variant{{port: 11207, name: "couchbases"}, {port: 11210, name: "couchbase"}}

	for _, variant := range variants {
		name := fmt.Sprintf("_%s._tcp.%s.%s", variant.name, cluster.ID, s.domainName)
		records := make([]route53types.ResourceRecord, 0, len(hostnames))
		for _, hostname := range hostnames {
			// Format: [priority] [weight] [port] [server host name]
			records = append(records, route53types.ResourceRecord{
				Value: aws.String(fmt.Sprintf("0 0 %d %s", variant.port, hostname)),
			})
		}
		changes = append(changes, route53types.Change{
			Action: action,
			ResourceRecordSet: &route53types.ResourceRecordSet{
				Name:            aws.String(name),
				Type:            route53types.RRTypeSrv,
				ResourceRecords: records,
				TTL:             aws.Int64(60),
			},
		})
	}

	_, err := s.route53Client.ChangeResourceRecordSets(ctx, &route53.ChangeResourceRecordSetsInput{
		ChangeBatch: &route53types.ChangeBatch{
			Changes: changes,
		},
		HostedZoneId: aws.String(s.hostedZoneId),
	})

	return err
}

func (s *EC2Service) runInstances(ctx context.Context, clusterID, serverVersion string, ami *string, instanceCount int, instanceType types.InstanceType) ([]string, error) {
	useSpotMarket := true

	for {
		input := &ec2.RunInstancesInput{
			MaxCount:         aws.Int32(int32(instanceCount)),
			MinCount:         aws.Int32(int32(instanceCount)),
			ImageId:          ami,
			InstanceType:     instanceType,
			KeyName:          aws.String(s.keyName),
			SecurityGroupIds: []string{*aws.String(s.securityGroup)},
			TagSpecifications: []types.TagSpecification{
				{
					ResourceType: "instance",
					Tags: []types.Tag{{
						Key:   aws.String("com.couchbase.dyncluster.cluster_id"),
						Value: aws.String(clusterID),
					}, {
						Key:   aws.String("com.couchbase.dyncluster.creator"),
						Value: aws.String(dyncontext.ContextUser(ctx)),
					}, {
						Key:   aws.String("com.couchbase.dyncluster.initial_server_version"),
						Value: aws.String(serverVersion),
					}, {
						Key:   aws.String("Owner"),
						Value: aws.String("SDK"),
					}},
				},
			},
		}

		if useSpotMarket {
			input.InstanceMarketOptions = &types.InstanceMarketOptionsRequest{
				MarketType: types.MarketTypeSpot,
			}
		}

		createdInstances, err := s.client.RunInstances(ctx, input)

		if err != nil {
			// the error could be because of insufficient spot capacity so
			// try requesting on demand instances
			if useSpotMarket {
				useSpotMarket = false
				continue
			} else {
				return nil, err
			}
		}

		instanceIds := make([]string, 0, instanceCount)
		for _, instance := range createdInstances.Instances {
			instanceIds = append(instanceIds, *instance.InstanceId)
		}

		return instanceIds, nil
	}
}

func (s *EC2Service) allocateNodes(ctx context.Context, clusterID string, opts []common.NodeOptions) ([]string, error) {
	log.Printf("Allocating nodes for cluster %s (requested by: %s)", clusterID, dyncontext.ContextUser(ctx))

	options := opts[0]

	imageName := options.VersionInfo.ToImageName("cbdyncluster")
	instanceCount := len(opts)

	out, err := s.client.DescribeImages(ctx, &ec2.DescribeImagesInput{
		Filters: []types.Filter{
			{
				Name:   aws.String("name"),
				Values: []string{(imageName)},
			},
		},
	})

	if err != nil {
		return nil, err
	}

	if len(out.Images) != 1 {
		return nil, errors.New("no image found")
	}

	ami := out.Images[0].ImageId
	instanceType := types.InstanceTypeM5Large
	if options.VersionInfo.Arch == "aarch64" {
		instanceType = types.InstanceTypeT4gLarge
	}

	var instanceIds []string

	instanceIds, err = s.runInstances(ctx, clusterID, options.ServerVersion, ami, instanceCount, instanceType)

	if err != nil {
		return nil, err
	}

	if len(instanceIds) != instanceCount {
		return nil, errors.New("could not create all instances")
	}

	// tag each instance after creation so each has a unique name
	for i, instanceId := range instanceIds {
		instanceName := fmt.Sprintf("dynclsr-%s-%s", clusterID, opts[i].Name)
		_, err := s.client.CreateTags(ctx, &ec2.CreateTagsInput{
			Resources: []string{instanceId},
			Tags: []types.Tag{{
				Key:   aws.String("Name"),
				Value: aws.String(instanceName),
			}, {
				Key:   aws.String("com.couchbase.dyncluster.node_name"),
				Value: aws.String(opts[i].Name),
			}},
		}, func(options *ec2.Options) {
			options.Retryer = retry.AddWithErrorCodes(options.Retryer, "InvalidInstanceID.NotFound")
		})
		if err != nil {
			return nil, err
		}
	}

	err = ec2.NewInstanceRunningWaiter(s.client).Wait(ctx, &ec2.DescribeInstancesInput{
		InstanceIds: instanceIds,
	}, 120*time.Second)

	if s.route53Enabled {
		cluster, err := s.GetCluster(ctx, clusterID)
		if err != nil {
			return nil, err
		}

		err = s.createSrvRecord(ctx, cluster)
		if err != nil {
			return nil, err
		}
	}

	return instanceIds, nil
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

	if s.route53Enabled {
		err = s.removeSrvRecord(ctx, c)
		if err != nil {
			return err
		}
	}

	err = s.terminateInstances(ctx, nodesToKill)
	if err != nil {
		return err
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
	meta, err := s.metaStore.GetClusterMeta(clusterID)
	if err != nil {
		return nil, err
	}
	if meta.OS == "" {
		return nil, errors.New("cluster does not have an OS specified")
	}
	opts.SSHKeyPath = s.keyPath
	opts.SSHUsername = osToSSHUsername[meta.OS]
	return common.SetupCertAuth(ctx, s, clusterID, opts)
}

func (s *EC2Service) SetupClusterEncryption(ctx context.Context, clusterID string, opts service.SetupClusterEncryptionOptions) error {
	return common.SetupClusterEncryption(ctx, s, clusterID, opts)
}

func (s *EC2Service) AddBucket(ctx context.Context, clusterID string, opts service.AddBucketOptions) error {
	return common.AddBucket(ctx, s, clusterID, opts)
}

func (s *EC2Service) AddSampleBucket(ctx context.Context, clusterID string, opts service.AddSampleOptions) error {
	return common.AddSampleBucket(ctx, s, clusterID, opts)
}

func (s *EC2Service) ConnString(ctx context.Context, clusterID string, useSSL, useSrv bool) (string, error) {
	if useSrv {
		prefix := "couchbase"
		if useSSL {
			prefix = "couchbases"
		}
		return fmt.Sprintf("%s://%s.%s", prefix, clusterID, s.domainName), nil
	}
	return common.ConnString(ctx, s, clusterID, useSSL)
}

func (s *EC2Service) terminateInstances(ctx context.Context, instanceIds []string) error {
	_, err := s.client.TerminateInstances(ctx, &ec2.TerminateInstancesInput{
		InstanceIds: instanceIds,
	})

	return err
}
