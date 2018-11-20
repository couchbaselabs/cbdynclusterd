package daemon

import (
	"context"
	"errors"
	"fmt"
	"log"
	"strconv"
	"strings"
	"time"

	"github.com/docker/docker/api/types"
	"github.com/docker/docker/api/types/container"
	"github.com/couchbaselabs/cbdynclusterd/helper"
	"github.com/golang/glog"
)
var NetworkName = "macvlan0"

type NodeOptions struct {
	Name          string
	Platform      string
	ServerVersion string
	VersionInfo   *NodeVersion
}

type NodeVersion struct {
	Version string
	Flavor  string
	Build   string
}

func (nv *NodeVersion) toTagName() string {
	if nv.Build == "" {
		return fmt.Sprintf("%s.centos7", nv.Version)
	}
	return fmt.Sprintf("%s-%s.centos7", nv.Version, nv.Build)
}

func (nv *NodeVersion) toImageName() string {
	return fmt.Sprintf("%s/dynclsr-couchbase_%s", dockerRegistry, nv.toTagName())
}

func (nv *NodeVersion) toPkgName() string {
	if nv.Build == "" {
		return fmt.Sprintf("couchbase-server-enterprise-%s-centos7.x86_64.rpm", nv.Version)
	}
	return fmt.Sprintf("couchbase-server-enterprise-%s-%s-centos7.x86_64.rpm", nv.Version, nv.Build)
}

func (nv *NodeVersion) toURL() string {
	// If there's no build number specified then the target is a release
	if nv.Build == "" {
		return fmt.Sprintf("http://172.23.120.24/builds/releases/%s", nv.Version)
	}
	return fmt.Sprintf("http://172.23.120.24/builds/latestbuilds/couchbase-server/%s/%s", nv.Flavor, nv.Build)
}

var versionToFlavor = map[string]map[string]string{
	"4": map[string]string{"0": "sherlock", "5": "watson"},
	"5": map[string]string{"0": "spock", "5": "vulcan"},
	"6": map[string]string{"0": "alice", "5": "mad-hatter"},
}

func flavorFromVersion(version string) (string, error) {
	versionSplit := strings.Split(version, ".")
	major := versionSplit[0]
	minor, err := strconv.Atoi(versionSplit[1])
	if err != nil {
		return "", errors.New("Could not convert version minor to int")
	}

	var minorS string
	if 5-minor <= 0 {
		minorS = "5"
	} else {
		minorS = "0"
	}

	flavor, ok := versionToFlavor[major][minorS]
	if !ok {
		return "", fmt.Errorf("%d.%d is not a recognised flavor", major, minor)
	}

	return flavor, nil
}

func parseServerVersion(version string) (*NodeVersion, error) {
	nodeVersion := NodeVersion{}
	versionParts := strings.Split(version, "-")
	flavor, err := flavorFromVersion(versionParts[0])
	if err != nil {
		return nil, err
	}
	nodeVersion.Version = versionParts[0]
	nodeVersion.Flavor = flavor
	if len(versionParts) > 1 {
		nodeVersion.Build = versionParts[1]
	}

	return &nodeVersion, nil
}

func allocateNode(ctx context.Context, clusterID string, timeout time.Time, opts NodeOptions) (string, error) {
	log.Printf("Allocating node for cluster %s (requested by: %s)", clusterID, ContextUser(ctx))

	containerName := fmt.Sprintf("dynclsr-%s-%s", clusterID, opts.Name)
	containerImage := opts.VersionInfo.toImageName()

	var dns []string
	if dnsHostFlag != "" {
		dns = append(dns, dnsHostFlag)
	}
	createResult, err := docker.ContainerCreate(context.Background(), &container.Config{
		Image: containerImage,
		Labels: map[string]string{
			"com.couchbase.dyncluster.creator":                ContextUser(ctx),
			"com.couchbase.dyncluster.cluster_id":             clusterID,
			"com.couchbase.dyncluster.node_name":              opts.Name,
			"com.couchbase.dyncluster.initial_server_version": opts.ServerVersion,
		},
		// same effect as ntp
		Volumes: map[string]struct{}{ "/etc/localtime:/etc/localtime": {} },
	}, &container.HostConfig{
		AutoRemove:  true,
		NetworkMode: container.NetworkMode(NetworkName),
		DNS: dns,
	}, nil, containerName)
	if err != nil {
		return "", err
	}

	err = docker.ContainerStart(context.Background(), createResult.ID, types.ContainerStartOptions{})
	if err != nil {
		return "", err
	}
	containerJSON, err := docker.ContainerInspect(context.Background(), createResult.ID)
	if err != nil {
		return "", err
	}
	ipv4 := containerJSON.NetworkSettings.Networks[NetworkName].IPAddress
	ipv6 := containerJSON.NetworkSettings.Networks[NetworkName].GlobalIPv6Address
	containerHostName := containerName+".couchbase.com"
	if ipv4 != "" {
		glog.Infof("register %s => %s on %s\n", ipv4, containerHostName, dnsHostFlag)
		body, err := registerDomainName(containerHostName, ipv4)
		if err != nil {
			glog.Warningf("Failed registering IPv4:%s, %s", err, body)
		}
	}
	if ipv6 != "" {
		body, err := registerDomainName(containerHostName, ipv6)
		glog.Warningf("Failed registering IPv6:%s, %s", err, body)
	}
	return createResult.ID, nil
}

// assign hostname to the IP in DNS server
func registerDomainName(hostname, ip string) (string, error){
	restParam := &helper.RestCall {
		ExpectedCode: 200,
		ContentType: "application/json",
		Method: "PUT",
		Cred: &helper.Cred {
			Hostname: dnsHostFlag,
			Port: 80,
		},
		Path: helper.Domain+"/"+hostname,
		Body: "{\"ips\":[\""+ip+"\"]}",
	}
	return helper.RestRetryer(helper.RestRetry, restParam, helper.GetResponse)
}

func killNode(ctx context.Context, containerID string) error {
	log.Printf("Killing node %s (requested by: %s)", containerID, ContextUser(ctx))

	err := docker.ContainerStop(context.Background(), containerID, nil)
	if err != nil {
		return err
	}

	// No need to kill the node, since we use `kill on stop` when creating the account
	/*
		err = docker.ContainerKill(context.Background(), containerID, "")
		if err != nil {
			return err
		}
	*/

	return nil
}
