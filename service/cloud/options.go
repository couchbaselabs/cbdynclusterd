package cloud

import (
	"github.com/couchbaselabs/cbdynclusterd/store"
)

type NodeSetupOptions struct {
	Services []string
	Size     uint32
}

type ClusterSetupOptions struct {
	Nodes       []NodeSetupOptions
	Environment *store.CloudEnvironment
	Region      string
	Provider    string
	SingleAZ    *bool
	EnvName     string
	Image       string
	Server      string
	IsColumnar  bool
}

type CreateColumnarOptions struct {
	Timeout     string
	Environment *store.CloudEnvironment
	Region      string
	Provider    string
	EnvName     string
	Nodes       int
}
