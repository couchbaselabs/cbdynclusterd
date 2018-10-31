package daemon

import (
	"strconv"
	"github.com/couchbaselabs/cbdynclusterd/helper"
	"github.com/couchbaselabs/cbdynclusterd/cluster"
)

type ClusterSetupOptions struct {
	Nodes []*Node
	Conf  CreateClusterSetupJSON
}

func SetupCluster(opts *ClusterSetupOptions) (string, error) {
	services := opts.Conf.Services

	initialNodes := opts.Nodes
	var nodes []*cluster.Node
	for i := 0; i < len(services); i++ {
		hostname := initialNodes[i].IPv4Address
		nodeHost := &cluster.Node {
			HostName: hostname,
			Port: strconv.Itoa(helper.RestPort),
			SshLogin:  &helper.Cred { Username:  helper.SshUser, Password:  helper.SshPass, Hostname: hostname, Port: helper.SshPort},
			RestLogin: &helper.Cred { Username: helper.RestUser, Password: helper.RestPass, Hostname: hostname, Port: helper.RestPort},
			N1qlLogin: &helper.Cred { Username: helper.RestUser, Password: helper.RestPass, Hostname: hostname, Port: helper.N1qlPort},
			FtsLogin:  &helper.Cred { Username: helper.RestUser, Password: helper.RestPass, Hostname: hostname, Port: helper.FtsPort},
			Services: services[i],
		}
		nodes = append(nodes, nodeHost)
	}

	config := cluster.Config {
		MemoryQuota: strconv.Itoa(opts.Conf.RamQuota),
		StorageMode: opts.Conf.StorageMode,
		User:        opts.Conf.User,
		Bucket:      opts.Conf.Bucket,
	}

	clusterManager := &cluster.Manager {
		Nodes: nodes,
		Config: config,
	}

	return clusterManager.StartCluster()
}
