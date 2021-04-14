package docker

import (
	"bytes"
	"github.com/couchbaselabs/cbdynclusterd/helper"
	"github.com/golang/glog"
	"sync"
)

const (
	ReleaseUrl = "http://latestbuilds.service.couchbase.com/builds/releases/"
	BuildUrl   = "http://latestbuilds.service.couchbase.com/builds/latestbuilds/couchbase-server/"
)

func Install(nodes []*Node, version, build string, isEnterprise bool) {
	var wg sync.WaitGroup
	for _, node := range nodes {
		wg.Add(1)
		go runNode(&wg, node, version, build, isEnterprise)
	}

	wg.Wait()
}

func runNode(wg *sync.WaitGroup, node *Node, version, build string, isEnterprise bool) {
	defer wg.Done()

	osInfo := node.GetSystemInfo()

	if helper.Slowlog {
		filename := "opcode-attributes.json"
		glog.Infof("Copying %s", filename)
		err := node.ScpToRemote(filename, "/root/")
		if err != nil {
			glog.Fatalf("Cannot copy %s to remote node: %s", filename, err)
		}
	}
	dlUrl := buildUrl(version, build, isEnterprise, &osInfo)

	filename := "cluster-install.py"
	glog.Infof("Copying %s to %s", filename, node.HostName)
	err := node.ScpToRemote("../../"+filename, "/root/")
	if err != nil {
		glog.Fatalf("Cannot copy %s to remote node: %s", filename, err)
	}

	var stdoutBuf, stderrBuf bytes.Buffer
	err = node.RunSsh(&stdoutBuf, &stderrBuf, "python "+filename+" "+dlUrl)
	if err != nil {
		glog.Fatalf("Failed installing %s:%s", dlUrl, err)
	}
}

func buildUrl(version, build string, isEnterprise bool, osInfo *OsInfo) string {
	// version format could be like 4.6.3(released), 5.5.0-beta(released) or 5.5.0(not released)
	//http://latestbuilds.service.couchbase.com/builds/releases/4.6.3/couchbase-server-enterprise-4.6.3                                   -centos7.x86_64.rpm
	//http://latestbuilds.service.couchbase.com/builds/releases/5.5.0-beta/couchbase-server-enterprise-5.5.0-beta                         -centos7.x86_64.rpm
	//http://latestbuilds.service.couchbase.com/builds/latestbuilds/couchbase-server/vulcan/2345/couchbase-server-community-5.5.0-2345    -centos7.x86_64.rpm

	var urlStr, flavor, buildType string

	buildType = "enterprise"
	if !isEnterprise {
		buildType = "community"
	}

	if len(build) == 0 {
		urlStr = ReleaseUrl + version + "/couchbase-server-" + buildType + "-" + version + "-"
	} else {
		major, minor, _ := helper.Tuple(version)
		if major == 4 {
			if minor < 5 {
				flavor = "sherlock"
			} else {
				flavor = "watson"
			}
		} else if major == 5 {
			if minor < 5 {
				flavor = "spock"
			} else {
				flavor = "vulcan"
			}
		} else if major == 6 {
			if minor < 5 {
				flavor = "alice"
			} else {
				flavor = "mad-hatter"
			}
		}
		urlStr = BuildUrl + flavor + "/" + build + "/couchbase-server-" + buildType + "-" + version + "-" + build + "-"
	}

	urlStr += osInfo.Platform + "." + osInfo.Arch + "." + osInfo.PackageType
	return urlStr

}
