package docker

import (
	"bytes"
	"crypto/rand"
	"crypto/rsa"
	"crypto/x509"
	"encoding/json"
	"errors"
	"fmt"
	"github.com/couchbaselabs/cbdynclusterd/cluster"
	"io"
	"log"
	"net/url"
	"os"
	"path"
	"strconv"
	"strings"
	"sync"
	"time"

	"github.com/pkg/sftp"

	"github.com/couchbaselabs/cbcerthelper"

	"github.com/couchbaselabs/cbdynclusterd/helper"
	"github.com/golang/glog"
	"github.com/hnakamur/go-scp"
	"golang.org/x/crypto/ssh"
)

const (
	Active         = "active"
	InactiveAdded  = "inactive_added"
	InactiveFailed = "inactive_failed"
	Unknown        = "unknown"
)

type RespNode struct {
	ClusterMembership string `json:"clusterMembership"`
	HostName          string `json:"hostname"`
	Status            string `json:"status""`
	NSOtpNode         string `json:"otpNode"`
}

type RespPoolsNodes struct {
	RespNodes []RespNode `json:"nodes"`
}

type Node struct {
	poolsNodes *RespPoolsNodes
	session    *ssh.Session
	SshLogin   *helper.Cred
	RestLogin  *helper.Cred
	N1qlLogin  *helper.Cred
	FtsLogin   *helper.Cred
	HostName   string
	Port       string
	Version    string
	Services   string
	OtpNode    string
}

type OsInfo struct {
	Arch        string
	Platform    string
	PackageType string
}

func (n *Node) getId() string {
	return fmt.Sprintf("%s:%s", n.HostName, n.Port)
}

func (n *Node) Rebalance(remaining, failedOver, toRemove []Node) error {
	var ejectedId []string
	var ejectedIds map[string]bool
	for _, n := range failedOver {
		ejectedId = append(ejectedId, n.OtpNode)
		ejectedIds[n.OtpNode] = true
	}

	var remainingId []string
	if len(remaining) == 0 {
		if err := n.Update(true); err != nil {
			return err
		}
		for _, n := range n.poolsNodes.RespNodes {
			if _, ok := ejectedIds[n.NSOtpNode]; ok {
				continue
			}
			remainingId = append(remainingId, n.NSOtpNode)
		}
	}

	for _, n := range toRemove {
		ejectedId = append(ejectedId, n.OtpNode)
	}

	body := fmt.Sprintf("knownNodes=%s&ejectedNodes=%s",
		url.QueryEscape(strings.Join(remainingId, ",")),
		url.QueryEscape(strings.Join(ejectedId, ",")))

	restParam := &helper.RestCall{
		ExpectedCode: 200,
		Method:       "POST",
		Path:         helper.PRebalance,
		Cred:         n.RestLogin,
		Body:         body,
		Header:       map[string]string{"Content-Type": "application/x-www-form-urlencoded"},
	}

	_, err := helper.RestRetryer(helper.RestRetry, restParam, helper.GetResponse)
	return err

}

func (n *Node) AddNode(newNode *Node, services string) error {
	body := fmt.Sprintf("user=%s&password=%s&hostname=%s&services=%s",
		n.RestLogin.Username, n.RestLogin.Password, newNode.HostName, url.QueryEscape(newNode.Services))
	glog.Infof("body:%s", body)

	restParam := &helper.RestCall{
		ExpectedCode: 200,
		RetryOnCode:  400,
		Method:       "POST",
		Path:         helper.PAddNode,
		Cred:         n.RestLogin,
		Body:         body,
		Header:       map[string]string{"Content-Type": "application/x-www-form-urlencoded"},
	}
	_, err := helper.RestRetryer(helper.RestRetry, restParam, helper.GetResponse)
	if err != nil {
		if strings.Contains(err.Error(), "user is missing") {
			glog.Infof("Sometimes server returns 400 although adding node was successful. File a bug?:%s", err)
			// actual server response is Response:400:["user is missing","password is missing","Hostname is required."]
			return nil
		}
		glog.Errorf("restParam:%s\nError:%s", restParam, err)
	}
	return err
}

func (n *Node) InitNewCluster(config Config) error {
	err := n.SetMemoryQuota(config.MemoryQuota)
	if err != nil {
		return err
	}
	if config.StorageMode != "" {
		glog.Infof("Set storage mode to %s", config.StorageMode)
		if err = n.SetStorageMode(config.StorageMode); err != nil {
			return err
		}
	}
	return n.Provision()
}

func (n *Node) Provision() error {
	body := fmt.Sprintf("port=SAME&username=%s&password=%s", n.RestLogin.Username, n.RestLogin.Password)

	restParam := &helper.RestCall{
		ExpectedCode: 200,
		Method:       "POST",
		Path:         helper.PSettingsWeb,
		Cred:         n.RestLogin,
		Body:         body,
		Header:       map[string]string{"Content-Type": "application/x-www-form-urlencoded"},
	}
	_, err := helper.RestRetryer(helper.RestRetry, restParam, helper.GetResponse)
	return err
}

func (n *Node) SetMemoryQuota(quota string) error {
	body := fmt.Sprintf("memoryQuota=%s", quota)

	restParam := &helper.RestCall{
		ExpectedCode: 200,
		Method:       "POST",
		Path:         helper.PPoolsDefault,
		Cred:         n.RestLogin,
		Body:         body,
		Header:       map[string]string{"Content-Type": "application/x-www-form-urlencoded"},
	}
	_, err := helper.RestRetryer(helper.RestRetry, restParam, helper.GetResponse)
	return err
}

func (n *Node) GetMemUsedStats(bucket string) (*helper.MemUsedStats, error) {
	var stdoutBuf, stderrBuf bytes.Buffer
	err := n.RunSsh(&stdoutBuf, &stderrBuf, "/opt/couchbase/bin/cbstats  localhost -u "+n.RestLogin.Username+" -p "+n.RestLogin.Password+" all -b "+bucket)
	if err != nil {
		return nil, err
	}

	lines := strings.Split(stdoutBuf.String(), "\n")

	actual, uncompressed := 0, 0
	for _, line := range lines {
		matched := helper.PattActual.FindStringSubmatch(line)
		if matched != nil {
			val, _ := strconv.Atoi(matched[1])
			actual += val
		}

		matched = helper.PattActualReplica.FindStringSubmatch(line)
		if matched != nil {
			val, _ := strconv.Atoi(matched[1])
			actual += val
		}

		matched = helper.PattUncompressed.FindStringSubmatch(line)
		if matched != nil {
			val, _ := strconv.Atoi(matched[1])
			uncompressed += val
		}

		matched = helper.PattUncompressedReplica.FindStringSubmatch(line)
		if matched != nil {
			val, _ := strconv.Atoi(matched[1])
			uncompressed += val
		}
	}

	return &helper.MemUsedStats{
		Used:         actual,
		Uncompressed: uncompressed,
	}, nil
}

func (n *Node) Rename(hostname string) error {
	body := fmt.Sprintf("hostname=%s", hostname)

	restParam := &helper.RestCall{
		ExpectedCode: 200,
		Method:       "POST",
		Path:         helper.PRename,
		Cred:         n.RestLogin,
		Body:         body,
		Header:       map[string]string{"Content-Type": "application/x-www-form-urlencoded"},
	}
	_, err := helper.RestRetryer(helper.RestRetry, restParam, helper.GetResponse)
	if err == nil {
		glog.Infof("Succesfully renamed to %s", hostname)
	} else {
		glog.Errorf("Error while renaming to %s:%s", hostname, err)
	}

	return err

}

func (n *Node) SetupMemoryQuota(memoryQuota int) error {
	body := fmt.Sprintf("memoryQuota=%d", memoryQuota)

	restParam := &helper.RestCall{
		ExpectedCode: 200,
		Method:       "POST",
		Path:         helper.PPoolsDefault,
		Cred:         n.RestLogin,
		Body:         body,
		Header:       map[string]string{"Content-Type": "application/x-www-form-urlencoded"},
	}
	_, err := helper.RestRetryer(helper.RestRetry, restParam, helper.GetResponse)
	if err == nil {
		glog.Infof("Succesfully set memoryQuota to %d", memoryQuota)
	} else {
		glog.Errorf("Error while setting memoryQuota:%s", err)
	}

	return err
}

func (n *Node) SetupInitialService() error {
	glog.Infof("SetupInitialService for %s", n.HostName)
	body := fmt.Sprintf("services=%s", url.QueryEscape(n.Services))

	restParam := &helper.RestCall{
		ExpectedCode: 200,
		RetryOnCode:  400,
		Method:       "POST",
		Path:         helper.PSetupServices,
		Cred:         n.RestLogin,
		Body:         body,
		Header:       map[string]string{"Content-Type": "application/x-www-form-urlencoded"},
	}
	_, err := helper.RestRetryer(20, restParam, helper.GetResponse)
	if err == nil {
		glog.Infof("SetupInitialService for %s with services %s", n.HostName, n.Services)
	} else {
		glog.Errorf("SetupInitialService:%s", err)
	}

	return err
}

func (n *Node) CreateFtsIndex(name, bucketType, bucket string) error {
	// Creates secondary index
	query := fmt.Sprintf("?sourceType=%s&indexType=fulltext-index&sourceName=%s",
		bucketType, bucket)

	restParam := &helper.RestCall{
		ExpectedCode: 200,
		Method:       "PUT",
		Path:         helper.PFts + "/" + name + query,
		Cred:         n.FtsLogin,
	}
	_, err := helper.RestRetryer(helper.RestRetry, restParam, helper.GetResponse)
	if err != nil && strings.Contains(err.Error(), "index with the same name already exists") {
		return nil
	}
	return err
}

func (n *Node) NetworkReset() error {
	var stdoutBuf, stderrBuf bytes.Buffer
	err := n.RunSsh(&stdoutBuf, &stderrBuf, "tc qdisc del dev eth0 root netem")

	if err != nil {
		glog.Error("StdOut:%s", stdoutBuf)
		glog.Error("StdErr:%s", stderrBuf)
	}
	return err
}

func (n *Node) NetworkDelay() error {
	var stdoutBuf, stderrBuf bytes.Buffer
	err := n.RunSsh(&stdoutBuf, &stderrBuf, "tc qdisc add dev eth0 root netem delay 500ms 200ms loss 10% 25%")

	if err != nil {
		glog.Error("StdOut:%s", stdoutBuf)
		glog.Error("StdErr:%s", stderrBuf)
	}
	return err
}

func (n *Node) CreateN1qlIndex(name, fields, bucket string) error {
	// Creates secondary index
	query := fmt.Sprintf("create index %s on `%s` (%s)", name, bucket, fields)
	body := fmt.Sprintf("statement=%s", url.QueryEscape(query))

	restParam := &helper.RestCall{
		ExpectedCode: 200,
		Method:       "POST",
		Path:         helper.PN1ql,
		Cred:         n.N1qlLogin,
		Body:         body,
		Header:       map[string]string{"Content-Type": "application/x-www-form-urlencoded"},
	}
	_, err := helper.RestRetryer(helper.RestRetry, restParam, helper.GetResponse)
	return err

}

func (n *Node) ChangeBucketCompression(bucket, mode string) error {
	body := fmt.Sprintf("name=%s&compressionMode=%s", bucket, mode)
	restParam := &helper.RestCall{
		ExpectedCode: 200,
		Method:       "POST",
		Path:         helper.PBuckets + "/" + bucket,
		Cred:         n.RestLogin,
		Body:         body,
		Header:       map[string]string{"Content-Type": "application/x-www-form-urlencoded"},
	}

	_, err := helper.RestRetryer(helper.RestRetry, restParam, helper.GetResponse)

	return err
}

func (n *Node) CreateBucket(conf *cluster.Bucket) error {
	body := fmt.Sprintf("bucketType=%s&name=%s&ramQuotaMB=%s",
		conf.Type, conf.Name, conf.RamQuotaMB)

	if conf.Type != helper.BucketMemcached {
		body = fmt.Sprintf("%s&replicaNumber=%d", body, conf.ReplicaCount)
	}
	if conf.Type == helper.BucketEphemeral {
		body = fmt.Sprintf("%s&evictionPolicy=%s", body, conf.EphEvictionPolicy)
	}
	restParam := &helper.RestCall{
		ExpectedCode: 202,
		Method:       "POST",
		Path:         helper.PBuckets,
		Cred:         n.RestLogin,
		Body:         body,
		Header:       map[string]string{"Content-Type": "application/x-www-form-urlencoded"},
	}

	_, err := helper.RestRetryer(helper.RestRetry, restParam, helper.GetResponse)

	return err
}

func (n *Node) LoadSample(s string) error {
	body := fmt.Sprintf("[\"%s\"]", s)
	restParam := &helper.RestCall{
		ExpectedCode: 202,
		Method:       "POST",
		Path:         helper.PSampleBucket,
		Cred:         n.RestLogin,
		Body:         body,
		Header:       map[string]string{"Content-Type": "application/x-www-form-urlencoded"},
	}

	_, err := helper.RestRetryer(helper.RestRetry, restParam, helper.GetResponse)
	if err != nil {
		return err
	}

	if err = n.WaitForBucketHealthy(s); err != nil {
		return err
	}

	return n.PollSampleBucket(s)
}

func (n *Node) CreateCollection(conf *cluster.Collection) error {
	posts := url.Values{}
	posts.Add("name", conf.Name)

	restParam := &helper.RestCall{
		ExpectedCode: 200,
		Method:       "POST",
		Path:         fmt.Sprintf("/pools/default/buckets/%s/scopes/%s/collections", conf.BucketName, conf.ScopeName),
		Cred:         n.RestLogin,
		Body:         posts.Encode(),
		Header:       map[string]string{"Content-Type": "application/x-www-form-urlencoded"},
	}

	_, err := helper.RestRetryer(helper.RestRetry, restParam, helper.GetResponse)

	return err
}

func (n *Node) WaitForBucketReady() error {
	chRes := make(chan []RespNode)
	for {
		if err := n.Update(true); err != nil {
			return err
		}
		go func() {
			chRes <- n.poolsNodes.RespNodes
		}()
		select {
		case res := <-chRes:
			isClusterHealthy := true
			for _, status := range res {
				if status.Status != "healthy" {
					isClusterHealthy = false
					glog.Info("Waiting for bucket ready")
					time.Sleep(1 * time.Second)
					break
				}
			}
			if isClusterHealthy {
				glog.Info("Bucket is ready")
				return nil
			}
		case <-time.After(helper.WaitTimeout):
			return errors.New("Timeout while waiting for bucket ready")
		}
	}
}

//WaitForBucketHealthy will wait until bucket with name s exists and that it is ready
func (n *Node) WaitForBucketHealthy(b string) error {
	params := &helper.RestCall{
		ExpectedCode: 200,
		RetryOnCode:  404,
		Method:       "GET",
		Path:         helper.PBuckets + "/" + b,
		Cred:         n.RestLogin,
	}
	_, err := helper.RestRetryer(10, params, helper.GetResponse)
	if err != nil {
		return err
	}

	return n.WaitForBucketReady()
}

func (n *Node) SetStorageMode(storageMode string) error {
	body := fmt.Sprintf("storageMode=%s", storageMode)
	restParam := &helper.RestCall{
		ExpectedCode: 200,
		Method:       "POST",
		Path:         helper.PSettingsIndexes,
		Cred:         n.RestLogin,
		Body:         body,
		Header:       map[string]string{"Content-Type": "application/x-www-form-urlencoded"},
	}

	_, err := helper.RestRetryer(helper.RestRetry, restParam, helper.GetResponse)

	return err
}

func (n *Node) EnableDeveloperPreview() error {
	restParam := &helper.RestCall{
		ExpectedCode: 200,
		Method:       "POST",
		Path:         helper.PDeveloperPreview,
		Cred:         n.RestLogin,
		Body:         "enabled=true",
		Header:       map[string]string{"Content-Type": "application/x-www-form-urlencoded"},
	}

	_, err := helper.RestRetryer(helper.RestRetry, restParam, helper.GetResponse)

	return err
}

func (n *Node) CreateUser(user *helper.UserOption) error {
	if user.Roles == nil {
		roles := []string{"admin"}
		user.Roles = &roles
	}
	body := fmt.Sprintf("name=%s&password=%s&roles=%s", user.Name, user.Password, strings.Join(*user.Roles, ","))
	restParam := &helper.RestCall{
		ExpectedCode: 200,
		Method:       "PUT",
		Path:         helper.PRbacUsers + "/" + user.Name,
		Cred:         n.RestLogin,
		Body:         body,
		Header:       map[string]string{"Content-Type": "application/x-www-form-urlencoded"},
	}

	_, err := helper.RestRetryer(helper.RestRetry, restParam, helper.GetResponse)

	return err
}

func (n *Node) DeleteBucket(name string) error {
	restParam := &helper.RestCall{
		ExpectedCode: 200,
		Method:       "DELETE",
		Path:         helper.PBuckets + "/" + name,
		Cred:         n.RestLogin,
	}

	_, err := helper.RestRetryer(helper.RestRetry, restParam, helper.GetResponse)

	return err

}

func (n *Node) PollJoinReady(chErr chan error) {
	var err error
	parsed := make(map[string]interface{})
	restParam := &helper.RestCall{
		ExpectedCode: 200,
		Method:       "GET",
		Path:         helper.PNodesSelf,
		Cred:         n.RestLogin,
	}
	info := make(chan map[string]interface{})
	var resp string

	for {
		if resp, err = helper.RestRetryer(helper.RestRetry, restParam, helper.GetResponse); err != nil {
			chErr <- err
			return
		}
		if err = json.Unmarshal([]byte(resp), &parsed); err != nil {
			chErr <- err
			return
		}
		go func() { info <- parsed }()

		select {
		case status := <-info:
			if status["clusterCompatibility"].(float64) > 0 {
				glog.Infof("%s is ready to join", n.HostName)
				chErr <- nil
				return
			} else {
				glog.Infof("%s is not ready to join, yet", n.HostName)
				time.Sleep(1 * time.Second)
			}
		case <-time.After(helper.RestTimeout):
			chErr <- errors.New("Timeout while polling join ready")
			return
		}

	}
}

func (n *Node) PollCompressionMode(bucket, mode string) error {
	var err error
	params := &helper.RestCall{
		ExpectedCode: 200,
		Method:       "GET",
		Path:         helper.PBuckets + "/" + bucket,
		Cred:         n.RestLogin,
	}

	info := make(chan map[string]interface{})

CompressionLoop:
	for {
		resp, err := helper.RestRetryer(helper.RestRetry, params, helper.GetResponse)
		if err != nil {
			return err
		}

		//glog.Infof("resp=%s", resp)
		var parsed map[string]interface{}
		if err := json.Unmarshal([]byte(resp), &parsed); err != nil {
			return err
		}

		go func() {
			info <- parsed
		}()
		select {
		case status := <-info:
			if status["compressionMode"].(string) == mode {
				err = nil
				glog.Infof("Compression mode switched to %s", mode)
				break CompressionLoop
			} else {
				err = nil
				glog.Infof("Compression mode is still %s", status["compressionMode"].(string))
				time.Sleep(1 * time.Second)
			}
		case <-time.After(helper.RestTimeout):
			err = errors.New("Timeout while checking compression mode")
			break CompressionLoop
		}
	}

	return err
}

func (n *Node) PollRebalance() error {
	var err error
	params := &helper.RestCall{
		ExpectedCode: 200,
		Method:       "GET",
		Path:         helper.PRebalanceProgress,
		Cred:         n.RestLogin,
	}

	info := make(chan map[string]interface{})

	for {
		resp, err := helper.RestRetryer(helper.RestRetry, params, helper.GetResponse)
		if err != nil {
			return err
		}

		glog.Infof("resp=%s", resp)
		var parsed map[string]interface{}
		if err := json.Unmarshal([]byte(resp), &parsed); err != nil {
			return err
		}

		go func() {
			glog.Infof("parsed=%v", parsed)
			info <- parsed
		}()
		select {
		case status := <-info:
			if status["status"].(string) == "none" {
				if status["errorMessage"] != nil {
					err = errors.New(status["errorMessage"].(string))
					glog.Infof("Rebalance failed:%s", err)
				} else {
					err = nil
					glog.Infof("Rebalance completed")
				}
				return err
			} else if status["status"].(string) == "running" {
				err = nil
				progress := parseRebalanceProgress(status)
				glog.Infof("Rebalance %d%%", progress)
				time.Sleep(1 * time.Second)
			}
		case <-time.After(helper.RestTimeout):
			return errors.New("Timeout while rebalancing")
		}
	}

	return err
}

func parseRebalanceProgress(status map[string]interface{}) int {
	cnt := 0
	progress := 0.0
	for k, v := range status {
		if k == "status" {
			continue
		}
		element := v.(map[string]interface{})
		glog.Infof("element=%v", element)
		progress += element["progress"].(float64)
		cnt++
	}
	glog.Infof("progress=%f, cnt=%d", progress, cnt)
	return int(progress*100) / cnt
}

func (n *Node) PollSampleBucket(s string) error {
	params := &helper.RestCall{
		ExpectedCode: 200,
		Method:       "GET",
		Path:         helper.PBuckets + "/" + s,
		Cred:         n.RestLogin,
	}

	deadline := time.Now().Add(8 * time.Minute)

	for {
		resp, err := helper.RestRetryer(helper.RestRetry, params, helper.GetResponse)
		if err != nil {
			return err
		}

		var parsed map[string]interface{}
		if err := json.Unmarshal([]byte(resp), &parsed); err != nil {
			return err
		}

		basicStats := parsed["basicStats"].(map[string]interface{})
		if basicStats["itemCount"].(float64) == helper.SampleBucketsCount[s] || basicStats["itemCount"].(float64) >= 2*helper.SampleBucketsCount[s] {
			glog.Infof("Sample bucket %s is loaded", s)
			return nil
		}
		if time.Now().After(deadline) {
			return errors.New("Timeout while loading sample bucket.")
		}
	}
}

func (n *Node) restCallToAux(fn func(RespNode, *helper.Cred, chan error), restLogin *helper.Cred) error {
	if n.poolsNodes == nil {
		if err := n.Update(false); err != nil {
			return err
		}
	}
	nodeId := n.getId()
	wait := 0
	var auxNodes []RespNode
	for _, nn := range n.poolsNodes.RespNodes {
		if nodeId == nn.HostName {
			continue
		}
		auxNodes = append(auxNodes, nn)
	}

	size := len(auxNodes)
	if size == 0 {
		return nil
	}

	chErr := make(chan error, size)

	for _, nn := range auxNodes {
		go fn(nn, restLogin, chErr)
		wait++ // waitgroup is not useful because, we want to return when any of goroutine fails
	}

	for {
		select {
		case res := <-chErr:
			wait--
			if res != nil || wait == 0 {
				return res
			}
		case <-time.After(helper.RestTimeout):
			return errors.New("Timeout while restCallToAux")
		}
	}
}

func (n *Node) FailOverAndEjectAll(restLogin *helper.Cred) error {
	return n.restCallToAux(failOverAndEject, restLogin)
}

func failOverAndEject(node RespNode, login *helper.Cred, chErr chan error) {

	if node.ClusterMembership != InactiveAdded {
		err := otpPost(node.NSOtpNode, helper.PFailover, login)
		if err != nil {
			chErr <- err
			return
		}

		time.Sleep(1 * time.Second) // find way to checking failover is done instead of sleeping
	}

	err := otpPost(node.NSOtpNode, helper.PEject, login)
	if err != nil {
		chErr <- err
		return
	}
	chErr <- nil

}

func otpPost(otpNode, path string, login *helper.Cred) error {
	body := "otpNode=" + otpNode
	glog.Infof("%s, postbody:%s", login.Hostname+"/"+path, body)

	restParam := &helper.RestCall{
		ExpectedCode: 200,
		Method:       "POST",
		Path:         path,
		Cred:         login,
		Body:         body,
	}
	_, err := helper.RestRetryer(helper.RestRetry, restParam, helper.GetResponse)
	return err
}

func (n *Node) Membership() (string, error) {
	thisHost := fmt.Sprintf("%s:%s", n.HostName, n.Port)
	for _, n := range n.poolsNodes.RespNodes {
		if n.HostName == thisHost {
			return n.ClusterMembership, nil
		}
	}

	return "", errors.New("Could not find node info of " + thisHost)

}

func (n *Node) GetBuckets() (*[]cluster.Bucket, error) {
	restParam := &helper.RestCall{
		ExpectedCode: 200,
		Method:       "GET",
		Path:         helper.PBuckets,
		Cred:         n.RestLogin,
	}
	resp, err := helper.RestRetryer(helper.RestRetry, restParam, helper.GetResponse)
	if err != nil {
		return nil, err
	}

	var buckets []cluster.Bucket
	err = json.Unmarshal([]byte(resp), &buckets)

	return &buckets, err

}

func (n *Node) Update(force bool) error {
	if n.poolsNodes != nil && !force {
		return nil
	}
	if n.poolsNodes == nil {
		n.poolsNodes = &RespPoolsNodes{}
	}
	restParam := &helper.RestCall{
		ExpectedCode: 200,
		Method:       "GET",
		Path:         helper.PPoolsNodes,
		Cred:         n.RestLogin,
	}
	resp, err := helper.RestRetryer(helper.RestRetry, restParam, helper.GetResponse)
	if err != nil {
		return err
	}

	nodeId := n.getId()
	if err := json.Unmarshal([]byte(resp), n.poolsNodes); err != nil {
		return err
	}
	for _, nd := range n.poolsNodes.RespNodes {
		if nd.HostName == nodeId {
			n.OtpNode = nd.NSOtpNode
		}
	}
	return nil
}

func (n *Node) StopRebalance() (string, error) {
	restParam := &helper.RestCall{
		ExpectedCode: 200,
		Method:       "POST",
		Path:         helper.PRebalanceStop,
		Cred:         n.RestLogin,
	}
	return helper.RestRetryer(helper.RestRetry, restParam, helper.GetResponse)
}

func (n *Node) GetInfo() (string, error) {
	restParam := &helper.RestCall{
		ExpectedCode: 200,
		Method:       "GET",
		Path:         helper.PPools,
		Cred:         n.RestLogin,
	}
	return helper.RestRetryer(helper.RestRetry, restParam, helper.GetResponse)
}

func (n *Node) StartServer(wg *sync.WaitGroup) {
	glog.Infof("In StartServer, my host is :%p:%s", n, n.HostName)
	/*var stdoutBuf, stderrBuf bytes.Buffer
	var cmdList []string
	cmdList = append(cmdList,"service couchbase-server start");
	cmdList = append(cmdList,"pkill -CONT -f memcached");
	cmdList = append(cmdList,"pkill -CONT -f beam.smp");
	cmdList = append(cmdList,"iptables -F");
	cmdList = append(cmdList,"iptables -t nat -F");

	for _, cmd := range cmdList {
		glog.Infof("running %s on %s", cmd, n.HostName)
		stdoutBuf.Reset()
		stderrBuf.Reset()
		err := n.RunSsh(&stdoutBuf, &stderrBuf, cmd)

		if err != nil { glog.Fatalf("Failed to start couchbase server:%s:%s", n.HostName, err) }
	}*/
	wg.Done()
}

func (n *Node) GetSystemInfo() OsInfo {
	var stdoutBuf, stderrBuf bytes.Buffer
	err := n.RunSsh(&stdoutBuf, &stderrBuf, "cat /etc/os-release")
	if err != nil {
		glog.Fatalf("Os Info:%s", err)
	}
	lines := strings.Split(stdoutBuf.String(), "\n")

	var id, version string
	for _, line := range lines {
		if len(id) == 0 {
			id, _ = helper.MatchingString("ID=\"([a-z]+)\"", line)
		}
		if len(version) == 0 {
			version, _ = helper.MatchingString("VERSION_ID=\"([0-9]+)\"", line)
		}
		if len(id) > 0 && len(version) > 0 {
			break
		}
	}

	if len(id) == 0 || len(version) == 0 {
		glog.Fatalf("Could not find server OS info")
	}

	stdoutBuf.Reset()
	err = n.RunSsh(&stdoutBuf, &stderrBuf, "lscpu")
	if err != nil {
		glog.Fatalf("System Info:%s", err)
	}
	lines = strings.Split(stdoutBuf.String(), "\n")

	var arch string
	for _, line := range lines {
		arch, _ = helper.MatchingString("Architecture:\\s*([^\\s]+)\\s*", line)
		if len(arch) > 0 {
			break
		}
	}

	packageType := "rpm"
	platform := id + version
	if id != "centos" {
		packageType = "deb"
		arch = "amd64"
	}

	return OsInfo{
		Arch:        arch,
		Platform:    platform,
		PackageType: packageType,
	}
}

func (n *Node) RunSsh(stdoutBuf *bytes.Buffer, stderrBuf *bytes.Buffer, cmd string) error {
	n.session = newSession(n.SshLogin)
	n.session.Stdout = stdoutBuf
	n.session.Stderr = stderrBuf

	defer n.session.Close()
	err := n.session.Run(cmd)
	if err != nil {
		if stderrBuf.Len() > 0 {
			return errors.New((*stderrBuf).String())
		} else {
			return err
		}
	}
	return nil
}

func (n *Node) ScpToRemote(src, dest string) error {
	var stderrBuf bytes.Buffer

	f, err := os.Open(src)
	if err != nil {
		return err
	}
	defer f.Close()

	s, err := f.Stat()
	if err != nil {
		return err
	}

	n.session = newSession(n.SshLogin)
	defer n.session.Close()

	n.session.Stderr = &stderrBuf
	w, err := n.session.StdinPipe()
	if err != nil {
		return err
	}

	if err := n.session.Start("scp -t " + dest); err != nil {
		w.Close()
		return err
	}

	result := make(chan error)

	go func() { result <- n.session.Wait() }()

	fmt.Fprintf(w, "C%#o %d %s\n", s.Mode().Perm(), s.Size(), path.Base(src))
	io.Copy(w, f)
	fmt.Fprint(w, "\x00")
	w.Close()

	err = <-result
	if len(stderrBuf.String()) > 0 {
		return errors.New(stderrBuf.String())
	} else {
		return err
	}
}

func (n *Node) ScpToLocal(src, dest string) error {

	sshClient, err := newClient(n.SshLogin)
	if err != nil {
		return err
	}
	scpHandle := scp.NewSCP(sshClient)

	return scpHandle.ReceiveFile(src, dest)
}

func (n *Node) ScpToLocalDir(src, dest string) error {

	sshClient, err := newClient(n.SshLogin)
	if err != nil {
		return err
	}
	scpHandle := scp.NewSCP(sshClient)

	return scpHandle.ReceiveDir(src, dest, nil)
}

func newClient(sshLogin *helper.Cred) (*ssh.Client, error) {
	sshConfig := &ssh.ClientConfig{
		User: sshLogin.Username,
		Auth: []ssh.AuthMethod{
			ssh.Password(sshLogin.Password),
		},
		HostKeyCallback: ssh.InsecureIgnoreHostKey(),
	}
	return ssh.Dial("tcp", fmt.Sprintf("%s:%d", sshLogin.Hostname, sshLogin.Port),
		sshConfig)

}

func newSession(sshLogin *helper.Cred) *ssh.Session {
	connection, err := newClient(sshLogin)

	if err != nil {
		glog.Fatalf("Failed to dial:%s", err)
	}

	session, err := connection.NewSession()
	if err != nil {
		glog.Fatalf(":%s", err)
	}

	return session
}

func (n *Node) SetupCert(ca *x509.Certificate, caPrivateKey *rsa.PrivateKey, now time.Time) error {
	nodePrivKey, err := rsa.GenerateKey(rand.Reader, 2048)
	if err != nil {
		return fmt.Errorf("failed to generate private key: %w", err)
	}

	nodeCSR, _, err := cbcerthelper.CreateNodeCertReq(nodePrivKey)
	if err != nil {
		return fmt.Errorf("failed to create certificate request: %w", err)
	}

	_, nodeCertBytes, err := cbcerthelper.CreateNodeCert(now, now.Add(365*24*time.Hour), caPrivateKey, n.HostName,
		ca, nodeCSR)
	if err != nil {
		return fmt.Errorf("failed to create node certificate: %w", err)
	}

	client, err := newClient(n.SshLogin)
	if err != nil {
		return fmt.Errorf("failed to create node ssh client: %w", err)
	}

	sftpClient, err := sftp.NewClient(client)
	if err != nil {
		return fmt.Errorf("failed to create node sftp client: %w", err)
	}

	err = sftpClient.Mkdir("/opt/couchbase/var/lib/couchbase/inbox")
	if err != nil {
		log.Printf("Failed to create node inbox: %s\n", err)
	}

	err = cbcerthelper.WriteRemoteCert("/opt/couchbase/var/lib/couchbase/inbox/chain.pem", "CERTIFICATE",
		nodeCertBytes, sftpClient)
	if err != nil {
		return fmt.Errorf("failed to write node certificate: %w", err)
	}

	err = cbcerthelper.WriteRemoteKey("/opt/couchbase/var/lib/couchbase/inbox/pkey.key", nodePrivKey, sftpClient)
	if err != nil {
		return fmt.Errorf("failed to write node key: %w", err)
	}

	err = cbcerthelper.UploadClusterCA(ca.Raw, n.RestLogin.Username, n.RestLogin.Password, n.HostName)
	if err != nil {
		return fmt.Errorf("failed to upload cluster CA: %w", err)
	}

	err = cbcerthelper.ReloadClusterCert(n.RestLogin.Username, n.RestLogin.Password, n.HostName)
	if err != nil {
		return fmt.Errorf("failed to reload cluster cert: %w", err)
	}

	err = cbcerthelper.EnableClientCertAuth(n.RestLogin.Username, n.RestLogin.Password, n.HostName)
	if err != nil {
		return fmt.Errorf("failed to enable client cert auth: %w", err)
	}

	return nil
}
