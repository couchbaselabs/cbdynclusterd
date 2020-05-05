package daemon

import (
	"context"
	"log"
	"strconv"

	"github.com/couchbaselabs/cbdynclusterd/helper"

	"github.com/couchbaselabs/cbdynclusterd/cluster"

	"github.com/pkg/errors"
)

type AddCollectionOptions struct {
	Conf AddCollectionJSON
}

func addCollection(ctx context.Context, clusterID string, opts AddCollectionOptions) error {
	log.Printf("Adding collection %s to bucket %s on cluster %s (requested by: %s)", opts.Conf.Name,
		opts.Conf.BucketName, clusterID, ContextUser(ctx))

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

	return node.CreateCollection(&cluster.Collection{
		Name:       opts.Conf.Name,
		ScopeName:  opts.Conf.ScopeName,
		BucketName: opts.Conf.BucketName,
	})
}
