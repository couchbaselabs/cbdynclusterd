package daemon

import (
	"strconv"

	"github.com/couchbaselabs/cbdynclusterd/cluster"
	"github.com/couchbaselabs/cbdynclusterd/helper"
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
		ipv4 := initialNodes[i].IPv4Address
		hostname := ipv4
		if opts.Conf.UseHostname {
			hostname = initialNodes[i].ContainerName[1:] + helper.DomainPostfix
		} else if opts.Conf.UseIpv6 {
			hostname = initialNodes[i].IPv6Address
		}

		nodeHost := &cluster.Node{
			HostName:  hostname,
			Port:      strconv.Itoa(helper.RestPort),
			SshLogin:  &helper.Cred{Username: helper.SshUser, Password: helper.SshPass, Hostname: ipv4, Port: helper.SshPort},
			RestLogin: &helper.Cred{Username: helper.RestUser, Password: helper.RestPass, Hostname: ipv4, Port: helper.RestPort},
			N1qlLogin: &helper.Cred{Username: helper.RestUser, Password: helper.RestPass, Hostname: ipv4, Port: helper.N1qlPort},
			FtsLogin:  &helper.Cred{Username: helper.RestUser, Password: helper.RestPass, Hostname: ipv4, Port: helper.FtsPort},
			Services:  services[i],
		}
		nodes = append(nodes, nodeHost)
	}

	config := cluster.Config{
		MemoryQuota:   strconv.Itoa(opts.Conf.RamQuota),
		StorageMode:   opts.Conf.StorageMode,
		User:          opts.Conf.User,
		Bucket:        opts.Conf.Bucket,
		UseHostname:   opts.Conf.UseHostname,
		UseDevPreview: opts.Conf.UseDeveloperPreview,
	}

	clusterManager := &cluster.Manager{
		Nodes:  nodes,
		Config: config,
	}

	return clusterManager.StartCluster()
}
