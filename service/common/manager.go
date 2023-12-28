package common

import (
	"bytes"
	"errors"
	"fmt"
	"io"
	"strconv"
	"strings"
	"time"

	"github.com/couchbaselabs/cbdynclusterd/cluster"

	"github.com/couchbaselabs/cbdynclusterd/helper"
	"github.com/golang/glog"
)

var (
	Version     *string
	Build       *string
	MemoryQuota *string
)

const (
	RestUsername = "Administrator"
	RestPassword = "password"
)

type Manager struct {
	Nodes  []*Node
	Config Config
	epNode int
}

type Pools struct {
	Name         string `json:"name"`
	Uri          string `json:"uri"`
	StreamingUri string `json:"streamingUri"`
}

type RefInfo struct {
	ClusterVersion string  `json:"implementationVersion"`
	Pools          []Pools `json:"pools"`
	ClusterId      string
	IsEnterprise   bool `json:"isEnterprise"`
}

type Config struct {
	MemoryQuota   string
	User          *helper.UserOption
	Version       helper.VersionTuple
	StorageMode   string
	Bucket        *helper.BucketOption
	UseHostname   bool
	UseDevPreview bool
}

func (m *Manager) StartCluster() (string, error) {
	existingCluster := make(map[string][]*Node)
	// Ensure we can connect to the REST port
	for _, n := range m.Nodes {
		info, err := n.GetInfo()
		if err != nil {
			return "", err
		}

		if info.Pools != nil && len(info.Pools) > 0 {
			info.ClusterId = info.Pools[0].Uri
			if len(info.ClusterId) > 0 {
				existingCluster[info.ClusterId] = append(existingCluster[info.ClusterId], n)
			}
		}
	}

	for _, n := range m.Nodes {
		_, err := n.StopRebalance()
		if err != nil {
			return "", err
		}
	}

	if len(existingCluster) > 0 {
		for _, n := range existingCluster {
			err := clearSingleCluster(n)
			if err != nil {
				return "", err
			}
		}
	}

	glog.Info("Server started. Setting up a cluster")
	return m.setupNewCluster()
}

func (m *Manager) pollJoinReadyAll(epnode *Node) error {
	chErr := make(chan error)
	size := 0
	for i, n := range m.Nodes {
		if i == m.epNode {
			continue
		}
		go n.PollJoinReady(chErr)
		size++
	}
	if size == 0 {
		return nil
	}
	finished := 0

	for {
		select {
		case res := <-chErr:
			finished++
			if res != nil || finished >= size {
				return res
			} else {
				glog.Infof("%d/%d node is ready to join", finished, size)
			}
		case <-time.After(helper.RestTimeout):
			return errors.New("timeout while polling rest of nodes")
		}
	}
}

func (m *Manager) setupNewCluster() (string, error) {
	m.epNode = 0 // select the first node as entry point
	epnode := m.Nodes[m.epNode]
	version := epnode.VersionTuple()

	memoryQuota, err := strconv.Atoi(m.Config.MemoryQuota)
	if err != nil {
		return "", err
	}

	clusterInitOpts := ClusterInitOpts{
		KVMemoryQuota:      memoryQuota,
		IndexerStorageMode: m.Config.StorageMode,
	}

	if err := epnode.ClusterInit(clusterInitOpts); err != nil {
		return "", err
	}

	// set minimum magma memory quota for >= neo (magma not supported on community edition)
	info, err := epnode.GetInfo()
	if err != nil {
		return "", err
	}
	if (version.Major > 7 || version.Major == 7 && version.Minor >= 1) && info.IsEnterprise {
		if err := epnode.SetLowMagmaMinMemoryQuote(); err != nil {
			return "", err
		}
	}

	if version.Major >= 5 && len(m.Config.User.Name) > 0 {
		glog.Info("CreateUser")
		if err := epnode.CreateUser(m.Config.User); err != nil {
			return "", err
		}
	}

	// check if rest of nodes are ready to join the cluster
	if err := m.pollJoinReadyAll(epnode); err != nil {
		return "", err
	}
	for i, n := range m.Nodes {
		if i == m.epNode {
			continue
		}
		glog.Infof("Adding %s to %s", n.HostName, epnode.HostName)
		if err := epnode.AddNode(n, n.Services); err != nil {
			if strings.Contains(err.Error(), "Prepare join failed. Got HTTP status 500 from REST call") {
				time.Sleep(5 * time.Second)
				glog.Infof("Adding %s to %s again", n.HostName, epnode.HostName)
				err = epnode.AddNode(n, n.Services)
			}
			if strings.Contains(err.Error(), "Prepare join failed. Node is already part of cluster.") {
				glog.Infof("Node is already part of the cluster, no need to add")
				err = nil
			}
			if err != nil {
				return "", err
			}
		}
	}

	// in case rebalance fails, just try one more time
	numRetry := 2
	for i := 0; i < numRetry; i++ {
		if err := epnode.Rebalance(nil, nil, nil); err != nil {
			return "", err
		}
		err := epnode.PollRebalance()
		if err == nil {
			glog.Infof("setupNewCluster() Rebalance completed")
			break
		} else if i < numRetry {
			glog.Infof("Rebalance failed, retrying:%s", err)
		} else {
			glog.Infof("Rebalance failed, exiting:%s", err)
			return "", err
		}
	}

	// create a bucket
	if len(m.Config.Bucket.Name) > 0 {
		if err = m.SetupBucket(m.Config.Bucket.Name, m.Config.Bucket.Type, m.Config.Bucket.Password, m.Config.Bucket.StorageBackend); err != nil {
			return "", err
		}
	}

	if m.Config.UseDevPreview {
		if err = m.EnableDeveloperPreview(); err != nil {
			return "", err
		}
	}

	return fmt.Sprintf("http://%s:%s", epnode.HostName, epnode.Port), nil
}

func getEpNode(force bool, nodes []*Node) (*Node, error) {
	// select epnode (entry point node)
	var epnode *Node
	for _, n := range nodes {
		n.Update(force) // get "nodes" array from the response of /pools/nodes
		membership, err := n.Membership()
		if err != nil {
			return nil, err
		}
		if membership == Active {
			epnode = n
			break
		}
	}
	if epnode == nil {
		return nil, errors.New("could not find active nodes")
	}
	return epnode, nil
}

func getFtsNode(force bool, nodes []*Node) (*Node, error) {
	return getServiceNode(force, "fts", nodes)
}

func getServiceNode(force bool, service string, nodes []*Node) (*Node, error) {
	var svcNode *Node
	for _, n := range nodes {
		n.Update(force) // get "nodes" array from the response of /pools/nodes
		if strings.Contains(n.Services, service) {
			svcNode = n
			break
		}
	}
	if svcNode == nil {
		return nil, errors.New("Could not find " + service + " nodes")
	}
	return svcNode, nil
}

func getN1qlNode(force bool, nodes []*Node) (*Node, error) {
	return getServiceNode(force, "n1ql", nodes)
}

func clearSingleCluster(nodes []*Node) error {

	epnode, err := getEpNode(true, nodes)

	if err != nil {
		return err
	}

	buckets, err := epnode.GetBuckets()

	if err != nil {
		return err
	}

	for _, b := range *buckets {
		err = epnode.DeleteBucket(b.Name)
		if err != nil {
			return err
		}
	}

	// Fail over and Eject
	err = epnode.FailOverAndEjectAll(&helper.Cred{
		Hostname: epnode.HostName,
		Port:     helper.RestPort,
		Username: RestUsername,
		Password: RestPassword,
	})
	if err != nil {
		return err
	}

	// reset master node

	glog.Infof("Reset the master node")
	cmd := "curl -d 'gen_server:cast(ns_cluster, leave).' -u "
	cmd += RestUsername + ":" + RestPassword
	cmd += " http://localhost:8091/diag/eval"
	var stdoutBuf, stderrBuf bytes.Buffer
	err = epnode.RunSsh(&stdoutBuf, &stderrBuf, cmd)

	// block till reset is done
	buff := make([]byte, 1024)
	for {
		n, err := stdoutBuf.Read(buff)
		glog.Infof("%q", buff[:n])
		if err == io.EOF {
			break
		}
	}
	return err
}

func (m *Manager) CreateUser(cred *helper.UserOption) error {
	epNode, err := getEpNode(false, m.Nodes)
	if err != nil {
		return err
	}
	if err = epNode.CreateUser(cred); err != nil {
		return err
	}
	return nil
}

func (m *Manager) EnableDeveloperPreview() error {
	epNode, err := getEpNode(false, m.Nodes)
	if err != nil {
		return err
	}
	if err = epNode.EnableDeveloperPreview(); err != nil {
		return err
	}
	return nil
}

func (m *Manager) CreateFtsIndex(name, bucketType, bucketName string) error {
	ftsNode, err := getFtsNode(false, m.Nodes)
	if err != nil {
		return err
	}
	if err := ftsNode.CreateFtsIndex(name, bucketType, bucketName); err != nil {
		// try with next fts node
		if strings.Contains(err.Error(), "failed to connect to or retrieve information from source") {
			newNodes := newNodesExcept(m.Nodes, ftsNode)
			ftsNode, err = getFtsNode(false, newNodes)
			if err != nil {
				return err
			}
			time.Sleep(3 * time.Second)
			glog.Infof("Retrying fts index creation with %s", ftsNode.HostName)
			return ftsNode.CreateFtsIndex(name, bucketType, bucketName)
		}
	}
	return nil
}

func newNodesExcept(nodes []*Node, except *Node) []*Node {

	var newNodes []*Node
	for _, n := range nodes {
		if n.HostName == except.HostName {
			continue
		}
		newNodes = append(newNodes, n)
	}

	return newNodes
}

func (m *Manager) NetworkReset() error {
	epNode, err := getEpNode(false, m.Nodes)
	if err != nil {
		return err
	}
	if err = epNode.NetworkReset(); err != nil {
		return err
	}
	return nil
}

func (m *Manager) NetworkDelay() error {
	epNode, err := getEpNode(false, m.Nodes)
	if err != nil {
		return err
	}
	if err = epNode.NetworkDelay(); err != nil {
		return err
	}
	return nil
}

func (m *Manager) GetEntryPoint() string {
	return m.Nodes[m.epNode].HostName
	//return fmt.Sprintf("%s:%s", m.Nodes[m.epNode].HostName, m.Nodes[m.epNode].Port)
}

func (m *Manager) CreateN1qlIndex(name, fields, bucket string) error {
	n1qlNode, err := getN1qlNode(false, m.Nodes)
	if err != nil {
		return err
	}
	if err := n1qlNode.CreateN1qlIndex(name, fields, bucket); err != nil {
		return err
	}
	return nil
}

func (m *Manager) ChangeBucketCompression(bucket, mode string) error {
	if err := m.Nodes[m.epNode].ChangeBucketCompression(bucket, mode); err != nil {
		return err
	}
	return m.Nodes[m.epNode].WaitForBucketReady()
}

func (m *Manager) SetupBucket(bucketName, bucketType, bucketPassword string, storageBackend string) error {
	var bType string
	switch bucketType {
	case "memcached":
		bType = helper.BucketMemcached
	case "ephemeral":
		bType = helper.BucketEphemeral
	default:
		bType = helper.BucketCouchbase
	}
	bc := cluster.Bucket{
		Name:              bucketName,
		Type:              bType,
		RamQuotaMB:        "256",
		ReplicaCount:      1,
		EphEvictionPolicy: "noEviction",
		StorageBackend:    storageBackend,
	}
	if err := m.Nodes[m.epNode].CreateBucket(&bc); err != nil {
		return err
	}

	return m.Nodes[m.epNode].WaitForBucketReady()
}
