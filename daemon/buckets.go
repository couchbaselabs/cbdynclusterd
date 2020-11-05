package daemon

import (
	"context"
	"log"
	"strconv"

	"github.com/couchbaselabs/cbdynclusterd/helper"

	"github.com/couchbaselabs/cbdynclusterd/cluster"

	"github.com/pkg/errors"
)

type AddBucketOptions struct {
	Conf AddBucketJSON
}

type AddSampleOptions struct {
	Conf AddSampleBucketJSON
}

func addBucket(ctx context.Context, clusterID string, opts AddBucketOptions) error {
	log.Printf("Adding bucket %s to cluster %s (requested by: %s)", opts.Conf.Name, clusterID, ContextUser(ctx))
	log.Printf("Bucket has Eviction policy  %s ", opts.Conf.EvictionPolicy)

	c, err := getCluster(ctx, clusterID)
	if err != nil {
		return err
	}

	if len(c.Nodes) == 0 {
		return errors.New("no nodes available")
	}

	n := c.Nodes[0]
	ipv4 := n.IPv4Address
	hostname := ipv4
	if opts.Conf.UseHostname {
		hostname = n.ContainerName[1:] + helper.DomainPostfix
	}

	node := &cluster.Node{
		HostName:  hostname,
		Port:      strconv.Itoa(helper.RestPort),
		SshLogin:  &helper.Cred{Username: helper.SshUser, Password: helper.SshPass, Hostname: ipv4, Port: helper.SshPort},
		RestLogin: &helper.Cred{Username: helper.RestUser, Password: helper.RestPass, Hostname: ipv4, Port: helper.RestPort},
	}

	return node.CreateBucket(&cluster.Bucket{
		Name:         opts.Conf.Name,
		Type:         opts.Conf.BucketType,
		ReplicaCount: opts.Conf.ReplicaCount,
		RamQuotaMB:   strconv.Itoa(opts.Conf.RamQuota),
		EphEvictionPolicy: opts.Conf.EvictionPolicy,
	})
}

func addSampleBucket(ctx context.Context, clusterID string, opts AddSampleOptions) error {
	log.Printf("Loading sample bucket %s to cluster %s (requested by: %s)", opts.Conf.SampleBucket, clusterID, ContextUser(ctx))

	if helper.SampleBucketsCount[opts.Conf.SampleBucket] == 0 {
		return errors.New("Unknown sample bucket")
	}

	c, err := getCluster(ctx, clusterID)
	if err != nil {
		return err
	}

	if len(c.Nodes) == 0 {
		return errors.New("no nodes available")
	}

	n := c.Nodes[0]
	ipv4 := n.IPv4Address
	hostname := ipv4
	if opts.Conf.UseHostname {
		hostname = n.ContainerName[1:] + helper.DomainPostfix
	}

	node := &cluster.Node{
		HostName:  hostname,
		Port:      strconv.Itoa(helper.RestPort),
		SshLogin:  &helper.Cred{Username: helper.SshUser, Password: helper.SshPass, Hostname: ipv4, Port: helper.SshPort},
		RestLogin: &helper.Cred{Username: helper.RestUser, Password: helper.RestPass, Hostname: ipv4, Port: helper.RestPort},
	}

	return node.LoadSample(opts.Conf.SampleBucket)
}
