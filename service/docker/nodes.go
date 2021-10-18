package docker

import (
	"context"
	"fmt"
	"log"
	"time"

	"github.com/couchbaselabs/cbdynclusterd/dyncontext"
	"github.com/couchbaselabs/cbdynclusterd/service/common"

	"github.com/couchbaselabs/cbdynclusterd/helper"
	"github.com/docker/docker/api/types"
	"github.com/docker/docker/api/types/container"
	"github.com/golang/glog"
)

var NetworkName = "macvlan0"

func (ds *DockerService) allocateNode(ctx context.Context, clusterID string, timeout time.Time, opts common.NodeOptions) (string, error) {
	log.Printf("Allocating node for cluster %s (requested by: %s)", clusterID, dyncontext.ContextUser(ctx))

	containerName := fmt.Sprintf("dynclsr-%s-%s", clusterID, opts.Name)
	containerImage := opts.VersionInfo.ToImageName(ds.dockerRegistry)

	var dns []string
	if ds.dnsSvcHost != "" {
		dns = append(dns, ds.dnsSvcHost)
	}
	createResult, err := ds.docker.ContainerCreate(context.Background(), &container.Config{
		Image: containerImage,
		Labels: map[string]string{
			"com.couchbase.dyncluster.creator":                dyncontext.ContextUser(ctx),
			"com.couchbase.dyncluster.cluster_id":             clusterID,
			"com.couchbase.dyncluster.node_name":              opts.Name,
			"com.couchbase.dyncluster.initial_server_version": opts.ServerVersion,
		},
		// same effect as ntp
		Volumes: map[string]struct{}{"/etc/localtime:/etc/localtime": {}},
	}, &container.HostConfig{
		AutoRemove:  true,
		NetworkMode: container.NetworkMode(NetworkName),
		DNS:         dns,
		CapAdd:      []string{"NET_ADMIN"},
	}, nil, containerName)
	if err != nil {
		return "", err
	}

	err = ds.docker.ContainerStart(context.Background(), createResult.ID, types.ContainerStartOptions{})
	if err != nil {
		return "", err
	}
	containerJSON, err := ds.docker.ContainerInspect(context.Background(), createResult.ID)
	if err != nil {
		return "", err
	}
	ipv4 := containerJSON.NetworkSettings.Networks[NetworkName].IPAddress
	ipv6 := containerJSON.NetworkSettings.Networks[NetworkName].GlobalIPv6Address
	containerHostName := containerName + ".couchbase.com"

	if ds.dnsSvcHost != "" {
		if ipv4 != "" {
			glog.Infof("register %s => %s on %s\n", ipv4, containerHostName, ds.dnsSvcHost)
			body, err := ds.registerDomainName(containerHostName, ipv4)
			if err != nil {
				glog.Warningf("Failed registering IPv4:%s, %s", err, body)
			}
		}

		if ipv6 != "" {
			glog.Infof("register %s => %s on %s\n", ipv6, containerHostName, ds.dnsSvcHost)
			body, err := ds.registerDomainName(containerHostName, ipv6)
			glog.Warningf("Failed registering IPv6:%s, %s", err, body)
		}
	}

	return createResult.ID, nil
}

// assign hostname to the IP in DNS server
func (ds *DockerService) registerDomainName(hostname, ip string) (string, error) {
	restParam := &helper.RestCall{
		ExpectedCode: 200,
		ContentType:  "application/json",
		Method:       "PUT",
		Cred: &helper.Cred{
			Hostname: ds.dnsSvcHost,
			Port:     80,
		},
		Path: helper.Domain + "/" + hostname,
		Body: "{\"ips\":[\"" + ip + "\"]}",
	}
	return helper.RestRetryer(helper.RestRetry, restParam, helper.GetResponse)
}

func (ds *DockerService) killNode(ctx context.Context, containerID string) error {
	log.Printf("Killing node %s (requested by: %s)", containerID, dyncontext.ContextUser(ctx))

	err := ds.docker.ContainerStop(context.Background(), containerID, nil)
	if err != nil {
		return err
	}

	// No need to kill the node, since we use `kill on stop` when creating the container
	/*
		err = docker.ContainerKill(context.Background(), containerID, "")
		if err != nil {
			return err
		}
	*/

	return nil
}
