package ec2

import (
	"context"
	"errors"
	"fmt"
	"io"
	"log"
	"net/http"
	"os"
	"strings"
	"sync"
	"time"

	"github.com/aws/aws-sdk-go-v2/aws"
	"github.com/aws/aws-sdk-go-v2/aws/retry"
	awsConfig "github.com/aws/aws-sdk-go-v2/config"
	"github.com/aws/aws-sdk-go-v2/service/ec2"
	"github.com/aws/aws-sdk-go-v2/service/ec2/types"
	"github.com/aws/aws-sdk-go-v2/service/route53"
	route53types "github.com/aws/aws-sdk-go-v2/service/route53/types"
	"github.com/couchbaselabs/cbdynclusterd/cluster"
	"github.com/couchbaselabs/cbdynclusterd/dyncontext"
	"github.com/couchbaselabs/cbdynclusterd/service"
	"github.com/couchbaselabs/cbdynclusterd/service/common"
	"github.com/couchbaselabs/cbdynclusterd/store"
)

var (
	ErrEC2NotEnabled = errors.New("ec2 is not enabled, credentials not set")

	errClusterNotFound = errors.New("cluster not found")
)

// route53API is the subset of the Route 53 client used by EC2Service, so it can be faked in tests.
type route53API interface {
	ListResourceRecordSets(ctx context.Context, params *route53.ListResourceRecordSetsInput, optFns ...func(*route53.Options)) (*route53.ListResourceRecordSetsOutput, error)
	ChangeResourceRecordSets(ctx context.Context, params *route53.ChangeResourceRecordSetsInput, optFns ...func(*route53.Options)) (*route53.ChangeResourceRecordSetsOutput, error)
}

type EC2Service struct {
	enabled               bool
	route53Enabled        bool
	metaStore             *store.ReadOnlyMetaDataStore
	client                *ec2.Client
	route53Client         route53API
	aliasRepoPath         string
	securityGroup         string
	keyName               string
	keyPath               string
	domainName            string
	hostedZoneId          string
	trustedRootCAPath     string
	trustedPrivateKeyPath string
	trustedCertPath       string

	buildingImages map[string]*[]chan error
	mu             sync.Mutex
}

type EC2Config struct {
	// Security group to use when creating ec2 instances
	SecurityGroup string `toml:"security-group"`
	// SSH key name to use when creating ec2 instances
	KeyName string `toml:"key-name"`
	// Path to the SSH private key to connect to ec2 instances
	KeyPath string `toml:"key-path"`
	// Domain name in route53 to use to create SRV records
	DomainName string `toml:"domain-name"`
	// Hosted zone in route53 to use to create SRV records
	HostedZoneId string `toml:"hosted-zone-id"`
	// Path to a trusted CA that signed the cert
	TrustedRootCAPath string `toml:"trusted-root-ca-path"`
	// Path to the private key of the signed cert
	TrustedPrivateKeyPath string `toml:"trusted-private-key-path"`
	// Path tp the public key of the signed cert
	TrustedCertPath string `toml:"trusted-cert-path"`
}

func NewEC2Service(config EC2Config, aliasRepoPath string, metaStore *store.ReadOnlyMetaDataStore) *EC2Service {
	enabled := true
	client := &ec2.Client{}
	route53Client := &route53.Client{}
	cfg, err := awsConfig.LoadDefaultConfig(context.TODO(), awsConfig.WithRetryer(func() aws.Retryer {
		return retry.AddWithMaxAttempts(retry.NewStandard(), 0) // keep retrying requests if the error is retryable
	}))
	if err != nil {
		enabled = false
	} else {
		client = ec2.NewFromConfig(cfg)
		route53Client = route53.NewFromConfig(cfg)
	}
	enabled = enabled && config.SecurityGroup != "" && config.KeyName != ""
	route53Enabled := config.DomainName != "" && config.HostedZoneId != ""
	log.Printf("EC2 enabled: %t", enabled)
	log.Printf("Route53 enabled: %t", route53Enabled)

	return &EC2Service{
		enabled:               enabled,
		route53Enabled:        route53Enabled,
		metaStore:             metaStore,
		client:                client,
		aliasRepoPath:         aliasRepoPath,
		keyName:               config.KeyName,
		keyPath:               config.KeyPath,
		securityGroup:         config.SecurityGroup,
		route53Client:         route53Client,
		hostedZoneId:          config.HostedZoneId,
		domainName:            config.DomainName,
		trustedRootCAPath:     config.TrustedRootCAPath,
		trustedPrivateKeyPath: config.TrustedPrivateKeyPath,
		trustedCertPath:       config.TrustedCertPath,

		buildingImages: make(map[string]*[]chan error),
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
		// Clean up with a fresh context, as the request context may be the reason allocation failed (e.g.
		// cancelled or timed out). Not found just means nothing was created before the failure.
		cleanupCtx, cancel := context.WithTimeout(dyncontext.NewContext(context.Background(), dyncontext.ContextUser(ctx), true), 5*time.Minute)
		defer cancel()

		killErr := s.KillCluster(cleanupCtx, opts.ClusterID)
		if killErr != nil && !errors.Is(killErr, errClusterNotFound) {
			log.Printf("Failed to clean up cluster %s after failed allocation: %v", opts.ClusterID, killErr)
			return fmt.Errorf("%w (cleanup of cluster %s also failed: %v)", err, opts.ClusterID, killErr)
		}

		return err
	}

	return nil
}

func (s *EC2Service) buildAMI(imageName string, nodeVersion *common.NodeVersion) error {
	log.Printf("Downloading build %s to /tmp", nodeVersion.ToPkgName())

	localFileName := fmt.Sprintf("/tmp/%s", nodeVersion.ToPkgName())
	remoteFileName := fmt.Sprintf("%s/%s", nodeVersion.ToURL(), nodeVersion.ToPkgName())

	file, err := os.Create(localFileName)
	if err != nil {
		return err
	}

	// Defers are FILO so we need to close the file before we can remove it.
	defer os.Remove(localFileName)
	defer file.Close()

	client := http.Client{}

	resp, err := client.Get(remoteFileName)
	if err != nil {
		return err
	}

	defer resp.Body.Close()

	_, err = io.Copy(file, resp.Body)
	if err != nil {
		return err
	}

	err = CallPacker(PackerOptions{
		BuildPkg:       nodeVersion.ToPkgName(),
		AmiName:        imageName,
		Arch:           nodeVersion.Arch,
		OS:             nodeVersion.OS,
		ServerlessMode: nodeVersion.ServerlessMode,
	})

	return err
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
	if waitChans, building := s.buildingImages[imageName]; building {
		waitChan := make(chan error)
		*waitChans = append(*waitChans, waitChan)
		s.mu.Unlock()
		log.Printf("Image %s is already being built, waiting...", imageName)
		select {
		case err := <-waitChan:
			return err
		case <-time.After(1 * time.Hour):
			return errors.New("timed out waiting for image to be built")
		}
	}

	waitChains := make([]chan error, 0)
	s.buildingImages[imageName] = &waitChains
	s.mu.Unlock()

	log.Printf("No image found for %s, building...", imageName)

	err = s.buildAMI(imageName, nodeVersion)

	// inform any waiters
	s.mu.Lock()
	for _, waitChan := range *s.buildingImages[imageName] {
		// waiter may not be listening anymore so have a fallback
		select {
		case waitChan <- err:
		default:
		}
	}
	delete(s.buildingImages, imageName)
	s.mu.Unlock()

	return err
}

func (s *EC2Service) srvName(clusterID string, secure bool) string {
	const (
		securePrefix   = "couchbases"
		insecurePrefix = "couchbase"
	)

	prefix := insecurePrefix
	if secure {
		prefix = securePrefix
	}

	return fmt.Sprintf("_%s._tcp.%s.%s", prefix, clusterID, s.domainName)

}

// clusterRecordSets returns every record set in the hosted zone that belongs to clusterID: the per-node
// A records (<node name>-<clusterID>.<domain>) and the secure/insecure SRV records. Records are looked up
// by name rather than built from the cluster's instances, so they are found whatever state the instances
// are in (stopped, terminated, partially running) and whatever IP each record currently holds.
func (s *EC2Service) clusterRecordSets(ctx context.Context, clusterID string) ([]route53types.ResourceRecordSet, error) {
	normalise := func(name string) string {
		return strings.ToLower(strings.TrimSuffix(name, ".")) + "."
	}

	aSuffix := normalise(fmt.Sprintf("-%s.%s", clusterID, s.domainName))
	srvNames := map[string]bool{
		normalise(s.srvName(clusterID, true)):  true,
		normalise(s.srvName(clusterID, false)): true,
	}

	var sets []route53types.ResourceRecordSet

	input := &route53.ListResourceRecordSetsInput{
		HostedZoneId: aws.String(s.hostedZoneId),
	}

	for {
		out, err := s.route53Client.ListResourceRecordSets(ctx, input)
		if err != nil {
			return nil, err
		}

		for _, set := range out.ResourceRecordSets {
			if set.Name == nil {
				continue
			}
			name := normalise(*set.Name)

			switch set.Type {
			case route53types.RRTypeA:
				// the node name must be a single label directly in front of the suffix
				nodeName := strings.TrimSuffix(name, aSuffix)
				if nodeName != name && nodeName != "" && !strings.Contains(nodeName, ".") {
					sets = append(sets, set)
				}
			case route53types.RRTypeSrv:
				if srvNames[name] {
					sets = append(sets, set)
				}
			}
		}

		if !out.IsTruncated {
			break
		}

		input.StartRecordName = out.NextRecordName
		input.StartRecordType = out.NextRecordType
		input.StartRecordIdentifier = out.NextRecordIdentifier
	}

	return sets, nil
}

// removeClusterRecords deletes every record set belonging to clusterID, using the values held by Route 53
// rather than the instances' current IPs (a delete only succeeds when the value matches exactly). It
// returns the number of record sets that were found.
func (s *EC2Service) removeClusterRecords(ctx context.Context, clusterID string) (int, error) {
	sets, err := s.clusterRecordSets(ctx, clusterID)
	if err != nil {
		return 0, err
	}

	if len(sets) == 0 {
		return 0, nil
	}

	err = s.deleteRecordSets(ctx, sets)
	if err == nil {
		return len(sets), nil
	}

	// A change batch is all or nothing, so retry one record set at a time so that a single bad record
	// can't stop the rest being removed.
	log.Printf("Failed to delete dns records for cluster %s in a single batch, retrying individually: %v", clusterID, err)

	var failures []string
	for _, set := range sets {
		err := s.deleteRecordSets(ctx, []route53types.ResourceRecordSet{set})
		if err != nil && !isRecordNotFound(err) {
			failures = append(failures, fmt.Sprintf("%s %s: %v", set.Type, aws.ToString(set.Name), err))
		}
	}

	if len(failures) > 0 {
		return len(sets), fmt.Errorf("failed to delete dns records for cluster %s: %s", clusterID, strings.Join(failures, "; "))
	}

	return len(sets), nil
}

func (s *EC2Service) deleteRecordSets(ctx context.Context, sets []route53types.ResourceRecordSet) error {
	changes := make([]route53types.Change, 0, len(sets))
	for i := range sets {
		changes = append(changes, route53types.Change{
			Action:            route53types.ChangeActionDelete,
			ResourceRecordSet: &sets[i],
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

// isRecordNotFound reports whether err is Route 53 rejecting a delete because the record set no longer
// exists, which means there is nothing left to clean up.
func isRecordNotFound(err error) bool {
	var invalidBatch *route53types.InvalidChangeBatch
	if !errors.As(err, &invalidBatch) {
		return false
	}

	messages := append([]string{aws.ToString(invalidBatch.Message)}, invalidBatch.Messages...)
	for _, message := range messages {
		if strings.Contains(message, "not found") {
			return true
		}
	}

	return false
}

func (s *EC2Service) createARecords(ctx context.Context, cluster *cluster.Cluster) error {
	return s.changeARecords(ctx, cluster, route53types.ChangeActionCreate)
}

func (s *EC2Service) createSrvRecords(ctx context.Context, cluster *cluster.Cluster) error {
	return s.changeSrvRecords(ctx, cluster, route53types.ChangeActionCreate)
}

func (s *EC2Service) changeSrvRecords(ctx context.Context, cluster *cluster.Cluster, action route53types.ChangeAction) error {
	hostnames := make([]string, 0, len(cluster.Nodes))
	for _, node := range cluster.Nodes {
		hostnames = append(hostnames, node.Hostname)
	}

	changes := make([]route53types.Change, 0, 2)

	type variant struct {
		port   int
		secure bool
	}

	// secure and insecure
	variants := []variant{{port: 11207, secure: true}, {port: 11210, secure: false}}

	for _, variant := range variants {
		name := s.srvName(cluster.ID, variant.secure)
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

func (s *EC2Service) changeARecords(ctx context.Context, cluster *cluster.Cluster, action route53types.ChangeAction) error {
	changes := make([]route53types.Change, 0, len(cluster.Nodes))
	for _, node := range cluster.Nodes {
		changes = append(changes, route53types.Change{
			Action: action,
			ResourceRecordSet: &route53types.ResourceRecordSet{
				Name: aws.String(node.Hostname),
				Type: route53types.RRTypeA,
				ResourceRecords: []route53types.ResourceRecord{
					{
						Value: aws.String(node.IPv4Address),
					},
				},
				TTL: aws.Int64(60),
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
	// Disabling spot market for now as most instances are getting terminated mid run
	useSpotMarket := false

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
	}, 2*time.Minute)
	if err != nil {
		return nil, err
	}

	// create dns records as quickly as possible so they have time to propagate
	if s.route53Enabled {
		cluster, err := s.GetCluster(ctx, clusterID)
		if err != nil {
			return nil, err
		}

		err = s.createARecords(ctx, cluster)
		if err != nil {
			return nil, err
		}

		// srv records point to the custom hostnames
		err = s.createSrvRecords(ctx, cluster)
		if err != nil {
			return nil, err
		}
	}

	if s.route53Enabled {
		// we need to wait until the instance is ready before we can ssh in and update the hosts file
		err = ec2.NewInstanceStatusOkWaiter(s.client).Wait(ctx, &ec2.DescribeInstanceStatusInput{
			InstanceIds: instanceIds,
		}, 5*time.Minute)
		if err != nil {
			return nil, err
		}

		connCtx, err := s.connectionContext(clusterID)
		if err != nil {
			return nil, err
		}

		// allow nodes to listen on custom hostnames
		err = common.UpdateHostsFile(ctx, s, clusterID, connCtx)
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

			hostname := *instance.PublicDnsName
			nodeName := tags["com.couchbase.dyncluster.node_name"]

			// use custom hostnames
			if s.route53Enabled {
				// e.g. node1-0e78c8d7.cbqeoc.com
				hostname = fmt.Sprintf("%s-%s.%s", nodeName, clusterID, s.domainName)
			}

			nodes = append(nodes, &cluster.Node{
				ContainerID:          *instance.InstanceId,
				ContainerName:        tags["Name"],
				State:                string(instance.State.Name),
				Name:                 nodeName,
				InitialServerVersion: tags["com.couchbase.dyncluster.initial_server_version"],
				IPv4Address:          *instance.PublicIpAddress,
				Hostname:             hostname,
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

func (s *EC2Service) AddUser(ctx context.Context, clusterID string, opts service.AddUserOptions, connCtx service.ConnectContext) error {
	return common.AddUser(ctx, s, clusterID, opts, connCtx)
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

	return nil, errClusterNotFound
}

func (s *EC2Service) KillCluster(ctx context.Context, clusterID string) error {
	if !s.enabled {
		return ErrEC2NotEnabled
	}

	log.Printf("Killing ec2 cluster %s (requested by: %s)", clusterID, dyncontext.ContextUser(ctx))

	// Ownership comes from the metadata store rather than GetCluster, which only sees running instances.
	if !dyncontext.ContextIgnoreOwnership(ctx) {
		meta, err := s.metaStore.GetClusterMeta(clusterID)
		if err != nil {
			return errClusterNotFound
		}

		if meta.Owner != dyncontext.ContextUser(ctx) {
			return errors.New("cannot kill clusters you don't own")
		}
	}

	instanceIds, err := s.getClusterInstanceIds(ctx, clusterID)
	if err != nil {
		return err
	}

	numRecords := 0
	if s.route53Enabled {
		// DNS must go before the instances: once an instance is terminated its public IP can be handed to
		// someone else, so if removal fails we leave the instances alone and return the error to retry later.
		numRecords, err = s.removeClusterRecords(ctx, clusterID)
		if err != nil {
			return err
		}
	}

	if len(instanceIds) == 0 && numRecords == 0 {
		return errClusterNotFound
	}

	if len(instanceIds) > 0 {
		err = s.terminateInstances(ctx, instanceIds)
		if err != nil {
			return err
		}
	}

	log.Printf("Killed ec2 cluster %s: terminated %d instances, removed %d dns record sets", clusterID, len(instanceIds), numRecords)

	return nil
}

// getClusterInstanceIds returns the IDs of every instance tagged with clusterID that has not already been
// terminated, including stopped and pending instances that GetCluster does not report.
func (s *EC2Service) getClusterInstanceIds(ctx context.Context, clusterID string) ([]string, error) {
	paginator := ec2.NewDescribeInstancesPaginator(s.client, &ec2.DescribeInstancesInput{
		Filters: []types.Filter{
			{Name: aws.String("tag:com.couchbase.dyncluster.cluster_id"), Values: []string{clusterID}},
			{Name: aws.String("instance-state-name"), Values: []string{
				string(types.InstanceStateNamePending),
				string(types.InstanceStateNameRunning),
				string(types.InstanceStateNameStopping),
				string(types.InstanceStateNameStopped),
			}},
		},
	})

	var instanceIds []string
	for paginator.HasMorePages() {
		out, err := paginator.NextPage(ctx)
		if err != nil {
			return nil, err
		}

		for _, reservation := range out.Reservations {
			for _, instance := range reservation.Instances {
				instanceIds = append(instanceIds, *instance.InstanceId)
			}
		}
	}

	return instanceIds, nil
}

func (s *EC2Service) KillAllClusters(ctx context.Context) error {
	log.Printf("Killing all ec2 clusters")
	return common.KillAllClusters(ctx, s)
}

func (s *EC2Service) AddCollection(ctx context.Context, clusterID string, opts service.AddCollectionOptions, connCtx service.ConnectContext) error {
	return common.AddCollection(ctx, s, clusterID, opts, connCtx)
}

func (s *EC2Service) SetupCertAuth(ctx context.Context, clusterID string, opts service.SetupClientCertAuthOptions, connCtx service.ConnectContext) (*service.CertAuthResult, error) {
	meta, err := s.metaStore.GetClusterMeta(clusterID)
	if err != nil {
		return nil, err
	}
	if meta.OS == "" {
		return nil, errors.New("cluster does not have an OS specified")
	}
	connCtx.SshKeyPath = s.keyPath
	connCtx.SshUsername = osToSSHUsername[meta.OS]
	return common.SetupCertAuth(ctx, s, clusterID, opts, connCtx)
}

func (s *EC2Service) SetupClusterEncryption(ctx context.Context, clusterID string, opts service.SetupClusterEncryptionOptions, connCtx service.ConnectContext) error {
	return common.SetupClusterEncryption(ctx, s, clusterID, opts, connCtx)
}

func (s *EC2Service) AddBucket(ctx context.Context, clusterID string, opts service.AddBucketOptions, connCtx service.ConnectContext) error {
	return common.AddBucket(ctx, s, clusterID, opts, connCtx)
}

func (s *EC2Service) AddSampleBucket(ctx context.Context, clusterID string, opts service.AddSampleOptions, connCtx service.ConnectContext) error {
	return common.AddSampleBucket(ctx, s, clusterID, opts, connCtx)
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

func (s *EC2Service) RunCBCollect(ctx context.Context, clusterID string) (*service.CBCollectResult, error) {
	connCtx, err := s.connectionContext(clusterID)
	if err != nil {
		return nil, err
	}
	return common.RunCBCollect(ctx, s, clusterID, connCtx)
}

func (s *EC2Service) connectionContext(clusterID string) (service.ConnectContext, error) {
	var connCtx service.ConnectContext
	meta, err := s.metaStore.GetClusterMeta(clusterID)
	if err != nil {
		return connCtx, err
	}

	if meta.OS == "" {
		return connCtx, errors.New("cluster does not have an OS specified")
	}

	connCtx.SshKeyPath = s.keyPath
	connCtx.SshUsername = osToSSHUsername[meta.OS]

	return connCtx, nil
}

func (s *EC2Service) SetupTrustedCert(ctx context.Context, clusterID string) error {
	connCtx, err := s.connectionContext(clusterID)
	if err != nil {
		return err
	}

	c, err := s.GetCluster(ctx, clusterID)
	if err != nil {
		return err
	}

	recv := make(chan error)

	var nodes []*common.Node
	for _, node := range c.Nodes {
		version := node.InitialServerVersion
		node := common.NewNode(node.Hostname, version, connCtx)
		nodes = append(nodes, node)
		go func(recv chan error, node *common.Node) {
			err := node.SetupTrustedCert(s.trustedRootCAPath, s.trustedPrivateKeyPath, s.trustedCertPath, version)
			recv <- err
		}(recv, node)
	}

	for range nodes {
		hostsErr := <-recv
		if hostsErr != nil {
			err = hostsErr
			continue
		}
	}

	return err
}

func (s *EC2Service) GetCertificate(ctx context.Context, clusterID string) (string, error) {
	return "", errors.New("not currently supported")
}
