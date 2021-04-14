package service

import (
	"github.com/couchbaselabs/cbdynclusterd/cluster"
	"github.com/couchbaselabs/cbdynclusterd/helper"
)

type AddCollectionOptions struct {
	Name        string
	ScopeName   string
	BucketName  string
	UseHostname bool
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

type SetupClientCertAuthOptions struct {
	Nodes     []*cluster.Node
	UserName  string
	UserEmail string
}

type AddBucketOptions struct {
	Name           string
	StorageMode    string
	RamQuota       int
	UseHostname    bool
	ReplicaCount   int
	BucketType     string
	EvictionPolicy string
}

type AddSampleOptions struct {
	SampleBucket string
	UseHostname  bool
}
