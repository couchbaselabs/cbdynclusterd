package common

import (
	"github.com/couchbaselabs/cbdynclusterd/cluster"
	"github.com/couchbaselabs/cbdynclusterd/helper"
	"time"
)

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
