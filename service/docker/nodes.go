package docker

import (
	"context"
	"errors"
	"fmt"
	"github.com/couchbaselabs/cbdynclusterd/dyncontext"
	"log"
	"strconv"
	"strings"
	"time"

	"github.com/couchbaselabs/cbdynclusterd/helper"
	"github.com/docker/docker/api/types"
	"github.com/docker/docker/api/types/container"
	"github.com/golang/glog"
)

var NetworkName = "macvlan0"

type Edition string

const (
	Enterprise Edition = "enterprise"
	Community  Edition = "community"
)

type CreateNodeOptions struct {
	Name                string
	Platform            string
	ServerVersion       string
	UseCommunityEdition bool
}

type nodeOptions struct {
	Name          string
	Platform      string
	ServerVersion string
	VersionInfo   *NodeVersion
}

type NodeVersion struct {
	Version string
	Flavor  string
	Build   string
	Edition Edition
}

func (nv *NodeVersion) toTagName() string {
	if nv.Build == "" {
		return fmt.Sprintf("%s.centos7", nv.Version)
	}
	return fmt.Sprintf("%s-%s.centos7", nv.Version, nv.Build)
}

func (nv *NodeVersion) toImageName(dockerRegistry string) string {
	return fmt.Sprintf("%s/dynclsr-couchbase_%s_%s", dockerRegistry, nv.Edition, nv.toTagName())
}

func (nv *NodeVersion) toPkgName() string {
	if nv.Build == "" {
		return fmt.Sprintf("couchbase-server-%s-%s-centos7.x86_64.rpm", nv.Edition, nv.Version)
	}
	return fmt.Sprintf("couchbase-server-%s-%s-%s-centos7.x86_64.rpm", nv.Edition, nv.Version, nv.Build)
}

func (nv *NodeVersion) toURL() string {
	// If there's no build number specified then the target is a release
	if nv.Build == "" {
		return fmt.Sprintf("%s%s", ReleaseUrl, nv.Version)
	}
	return fmt.Sprintf("%s%s/%s", BuildUrl, nv.Flavor, nv.Build)
}

var versionToFlavor = map[int]map[int]string{
	4: {0: "sherlock", 5: "watson"},
	5: {0: "spock", 5: "vulcan"},
	6: {0: "alice", 5: "mad-hatter"},
	7: {0: "cheshire-cat"},
}

func flavorFromVersion(version string) (string, error) {
	versionSplit := strings.Split(version, ".")

	major, err := strconv.Atoi(versionSplit[0])
	if err != nil {
		return "", errors.New("Could not convert version major to int")
	}

	minor, err := strconv.Atoi(versionSplit[1])
	if err != nil {
		return "", errors.New("Could not convert version minor to int")
	}

	if minor >= 5 {
		minor = 5
	} else {
		minor = 0
	}

	flavor, ok := versionToFlavor[major][minor]
	if !ok {
		return "", fmt.Errorf("%d.%d is not a recognised flavor", major, minor)
	}

	return flavor, nil
}

func parseServerVersion(version string, useCE bool) (*NodeVersion, error) {
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
	if useCE {
		nodeVersion.Edition = Community
	} else {
		nodeVersion.Edition = Enterprise
	}

	return &nodeVersion, nil
}

func (ds *DockerService) aliasServerVersion(version string) (string, error) {
	//Check for aliasing format: M.m-stable/release
	buildParts := strings.Split(version, "-")
	if len(buildParts) < 2 {
		return version, nil
	}

	versionParts := strings.Split(buildParts[0], ".")
	if len(versionParts) > 2 {
		return version, nil
	}

	p, err := ds.getProductsMap()
	if err != nil {
		return "", err
	}

	var serverBuild string
	if buildParts[1] == "release" {
		serverBuild = p["couchbase-server"][buildParts[0]].Release
	} else if buildParts[1] == "stable" {
		//Stable version should always have a result
		serverBuild = p["couchbase-server"][buildParts[0]].Stable
	}

	if serverBuild == "" {
		return "", fmt.Errorf("No build version found for %s", version)
	}

	log.Printf("Using %s version for %s -> %s", buildParts[1], buildParts[0], serverBuild)
	return serverBuild, nil
}

func (ds *DockerService) allocateNode(ctx context.Context, clusterID string, timeout time.Time, opts nodeOptions) (string, error) {
	log.Printf("Allocating node for cluster %s (requested by: %s)", clusterID, dyncontext.ContextUser(ctx))

	containerName := fmt.Sprintf("dynclsr-%s-%s", clusterID, opts.Name)
	containerImage := opts.VersionInfo.toImageName(ds.dockerRegistry)

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
