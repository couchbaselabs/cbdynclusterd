package docker

import (
	"github.com/couchbaselabs/cbdynclusterd/cluster"
	"github.com/couchbaselabs/cbdynclusterd/helper"
	"time"
)

type AllocateClusterOptions struct {
	Deadline time.Time
	Nodes    []CreateNodeOptions
}

type ClusterSetupOptions struct {
	Services            []string
	Nodes               []*cluster.Node
	UseHostname         bool
	UseIpv6             bool
	MemoryQuota         string
	User                *helper.UserOption
	StorageMode         string
	Bucket              *helper.BucketOption
	UseDeveloperPreview bool
}
