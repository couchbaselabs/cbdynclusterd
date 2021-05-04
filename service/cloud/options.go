package cloud

import "github.com/couchbaselabs/cbdynclusterd/helper"

type NodeSetupOptions struct {
	Services []string
	Size     uint32
}

type ClusterSetupOptions struct {
	Nodes   []NodeSetupOptions
	Version string
	Bucket  string
	User    *helper.UserOption
}
