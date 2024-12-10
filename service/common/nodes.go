package common

import (
	"errors"
	"fmt"
	"log"
	"strconv"
	"strings"

	"github.com/couchbaselabs/cbdynclusterd/service"
)

type Edition string

const (
	Enterprise Edition = "enterprise"
	Community  Edition = "community"
)

type NodeOptions struct {
	Name          string
	Platform      string
	ServerVersion string
	VersionInfo   *NodeVersion
}

type NodeVersion struct {
	Version        string
	Flavor         string
	Build          string
	Edition        Edition
	OS             string
	Arch           string
	ServerlessMode bool
}

func (nv *NodeVersion) ToTagName() string {
	var tagName string
	if nv.Build == "" {
		tagName = fmt.Sprintf("%s.%s.%s", nv.Version, nv.OS, nv.Arch)
	} else {
		tagName = fmt.Sprintf("%s-%s.%s.%s", nv.Version, nv.Build, nv.OS, nv.Arch)
	}
	if nv.ServerlessMode {
		tagName += "-serverless"
	}
	return tagName
}

func (nv *NodeVersion) ToImageName(prefix string) string {
	return fmt.Sprintf("%s/dynclsr-couchbase_%s_%s", prefix, nv.Edition, nv.ToTagName())
}

func (nv *NodeVersion) PkgExtension() string {
	if isRPM(nv.OS) {
		return "rpm"
	} else if strings.HasPrefix(nv.OS, "ubuntu") || strings.HasPrefix(nv.OS, "debian") {
		return "deb"
	} else {
		return ""
	}
}

func isRPM(os string) bool {
	return strings.HasPrefix(os, "centos") || strings.HasPrefix(os, "rhel") || strings.HasPrefix(os, "amzn2") || strings.HasPrefix(os, "oel") || strings.HasPrefix(os, "suse") || strings.HasPrefix(os, "linux")
}

func (nv *NodeVersion) pkgArch() string {
	if nv.Arch == "x86_64" || nv.Arch == "aarch64" {
		return "." + nv.Arch
	} else if nv.Arch == "amd64" {
		return "-" + nv.Arch
	} else {
		return ""
	}
}

func (nv *NodeVersion) ToPkgName() string {
	if nv.Build == "" {
		return fmt.Sprintf("couchbase-server-%s-%s-%s%s.%s", nv.Edition, nv.Version, nv.OS, nv.pkgArch(), nv.PkgExtension())
	}
	return fmt.Sprintf("couchbase-server-%s-%s-%s-%s%s.%s", nv.Edition, nv.Version, nv.Build, nv.OS, nv.pkgArch(), nv.PkgExtension())
}

func (nv *NodeVersion) ToURL() string {
	// If there's no build number specified then the target is a release
	if nv.Build == "" {
		return fmt.Sprintf("%s%s", ReleaseUrl, nv.Version)
	}
	return fmt.Sprintf("%s%s/%s", BuildUrl, nv.Flavor, nv.Build)
}

var versionToFlavor = map[int]map[int]string{
	4: {0: "sherlock", 5: "watson"},
	5: {0: "spock", 5: "vulcan"},
	6: {0: "alice", 5: "mad-hatter", 6: "mad-hatter"},
	7: {0: "cheshire-cat", 1: "neo", 2: "neo", 5: "elixir", 6: "trinity", 7: "cypher"},
	8: {0: "morpheus"},
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

	flavor, ok := versionToFlavor[major][minor]
	if !ok {
		return "", fmt.Errorf("%d.%d is not a recognised flavor", major, minor)
	}

	return flavor, nil
}

func ParseServerVersion(version, os, arch string, useCE, serverlessMode bool) (*NodeVersion, error) {
	nodeVersion := NodeVersion{}

	if arch == "" {
		if isRPM(os) {
			arch = "x86_64"
		} else {
			arch = "amd64"
		}
	}
	nodeVersion.Arch = arch
	versionParts := strings.Split(version, "-")
	flavor, err := flavorFromVersion(versionParts[0])
	if err != nil {
		return nil, err
	}
	nodeVersion.Version = versionParts[0]
	nodeVersion.Flavor = flavor
	if os == "" {
		os = "centos7"
	}
	if flavor == "trinity" || flavor == "cypher" || flavor == "morpheus" {
		os = "linux"
	}
	nodeVersion.OS = os

	if len(versionParts) > 1 {
		nodeVersion.Build = versionParts[1]
	}
	if useCE {
		nodeVersion.Edition = Community
	} else {
		nodeVersion.Edition = Enterprise
	}
	nodeVersion.ServerlessMode = serverlessMode

	return &nodeVersion, nil
}

func AliasServerVersion(version, aliasRepoPath string) (string, error) {
	// Check for aliasing format: M.m-stable/release
	buildParts := strings.Split(version, "-")
	if len(buildParts) < 2 {
		return version, nil
	}

	versionParts := strings.Split(buildParts[0], ".")
	if len(versionParts) > 2 {
		return version, nil
	}

	p, err := getProductsMap(aliasRepoPath)
	if err != nil {
		return "", err
	}

	var serverBuild string
	if buildParts[1] == "release" {
		serverBuild = p["couchbase-server"][buildParts[0]].Release
	} else if buildParts[1] == "stable" {
		// Stable version should always have a result
		serverBuild = p["couchbase-server"][buildParts[0]].Stable
	}

	if serverBuild == "" {
		return "", fmt.Errorf("No build version found for %s", version)
	}

	log.Printf("Using %s version for %s -> %s", buildParts[1], buildParts[0], serverBuild)
	return serverBuild, nil
}

func CreateNodesToAllocate(nodes []service.CreateNodeOptions, aliasRepoPath string) ([]NodeOptions, error) {
	var nodesToAllocate []NodeOptions
	for nodeIdx, node := range nodes {
		finalVersion, err := AliasServerVersion(node.ServerVersion, aliasRepoPath)
		if err != nil {
			return nil, err
		}

		nodeVersion, err := ParseServerVersion(finalVersion, node.OS, node.Arch, node.UseCommunityEdition, node.ServerlessMode)
		if err != nil {
			return nil, err
		}

		nodeToAllocate := NodeOptions{
			Name:          node.Name,
			Platform:      node.Platform,
			ServerVersion: finalVersion,
			VersionInfo:   nodeVersion,
		}
		if nodeToAllocate.Name == "" {
			nodeToAllocate.Name = fmt.Sprintf("node%d", nodeIdx+1)
		}

		nodesToAllocate = append(nodesToAllocate, nodeToAllocate)
	}

	return nodesToAllocate, nil
}
