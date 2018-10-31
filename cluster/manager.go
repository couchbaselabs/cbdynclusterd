package cluster

import (
	"github.com/golang/glog"
	"strings"
	"strconv"
	"os"
	"bufio"
	"encoding/json"
	"errors"
	"sync"
	"fmt"
	"time"
	"bytes"
	"io"
	"github.com/couchbaselabs/cbdynclusterd/helper"
)


var (
	Version *string
	Build   *string
	MemoryQuota *string
)

const (
	RestUsername = "Administrator"
	RestPassword = "password"
)

type Manager struct {
	Nodes []*Node
	Config Config
	epNode int
}

type Pools struct {
	Name string `json:name`
	Uri  string `json:uri`
	StreamingUri string `json:streamingUri`
}

type RefInfo struct {
	ClusterVersion string `json:"implementationVersion"`
	Pools []Pools `json:"pools""`
	ClusterId     string
}

type VersionTuple struct {
	Major int
	Minor int
	Patch int
}

func (v *VersionTuple) String() string {
	return fmt.Sprintf("%d-%d-%d", v.Major, v.Minor, v.Patch)
}

type Config struct {
	MemoryQuota  string
	User         *helper.UserOption
	Version      VersionTuple
	StorageMode  string
	Bucket       *helper.BucketOption
	IsEnterprise bool
}

func (m *Manager) GetMemUsedStats(bucket string) (*helper.MemUsedStats, error) {
	ret := &helper.MemUsedStats{}
	for _, n := range m.Nodes {
		curr, err := n.GetMemUsedStats(bucket)
		if err != nil {
			return nil, err
		}
		ret.Uncompressed += curr.Uncompressed
		ret.Used += curr.Used
	}
	return ret, nil
}

func (m *Manager) ScpToLocal(hostname, src, dest string) error {
	for _, nn := range m.Nodes {
		if nn.HostName == hostname {
			return nn.ScpToLocal(src, dest)
		}
	}
	return errors.New("Can not find matching host"+hostname)
}

func (m *Manager) ScpToLocalDir(hostname, src, dest string) error {
	for _, nn := range m.Nodes {
		if nn.HostName == hostname {
			return nn.ScpToLocalDir(src, dest)
		}
	}
	return errors.New("Can not find matching host"+hostname)
}

func (m *Manager) StartCluster() (string, error) {

	var refInfo RefInfo
	existingCluster := make(map[string][]*Node)
	// Ensure we can connect to the REST port
	for _, n := range m.Nodes {
		info, err := n.GetInfo()
		if err != nil { return "", err }

		err = json.Unmarshal([]byte(info), &refInfo)
		if err != nil { return "", err }

		if refInfo.Pools != nil && len(refInfo.Pools) > 0 {
			refInfo.ClusterId = refInfo.Pools[0].Uri
			if len(refInfo.ClusterId) > 0 {
				existingCluster[refInfo.ClusterId] = append(existingCluster[refInfo.ClusterId], n)
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
			if err != nil { return "", err }
		}
	}
	wg := sync.WaitGroup{}
	for _, n := range m.Nodes {
		wg.Add(1)
		glog.Infof("Calling n.StartServer for n:%p:%s", n, n.HostName)
		go n.StartServer(&wg)
	}
	wg.Wait()

	glog.Info("Server started. Setting up a cluster")
	return m.setupNewCluster()
}

func (m *Manager) Rebalance() error {
	epnode := m.Nodes[m.epNode]

	// in case rebalance fails, just try one more time
	numRetry := 2
	for i := 0 ; i < numRetry; i++ {
		if err := epnode.Rebalance(nil, nil, nil); err != nil { return err }
		err := epnode.PollRebalance()
		if err == nil {
			break
		} else if i < numRetry {
			glog.Infof("Rebalance failed, retrying:%s", err)
		} else {
			glog.Infof("Rebalance failed, exiting:%s", err)
			return err
		}
	}
	return nil
}

func (m *Manager) pollJoinReadyAll(epnode *Node) error {
	chErr := make(chan error)
	size := 0
	for i, n := range m.Nodes {
		if i == m.epNode {continue}
		go n.PollJoinReady(chErr)
		size++
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
			return errors.New("Timeout while polling rest of nodes")
		}
	}
}

func (m *Manager) setupNewCluster() (string, error) {
	m.epNode = 0 // select the first node as entry point
	epnode := m.Nodes[m.epNode]
	version, err := getVersion(epnode)
	if err != nil { return "", err}

	memoryQuota, err := strconv.Atoi(m.Config.MemoryQuota)
	if err != nil { return "", err }
	glog.Infof("Set data memory quota to %d", memoryQuota)
	if err := epnode.SetupMemoryQuota(memoryQuota); err != nil { return "", err }

	glog.Info("SetupInititalService")
	if err := epnode.SetupInitialService(); err != nil { return "", err }

	if err := epnode.InitNewCluster(m.Config); err != nil { return "", err }

	if version.Major >=5 && len(m.Config.User.Name) > 0 {
		glog.Info("CreateUser")
		if err := epnode.CreateUser(m.Config.User); err != nil { return "", err }
	}

	// check if rest of nodes are ready to join the cluster
	if err := m.pollJoinReadyAll(epnode); err != nil { return "", err }
	for i, n := range m.Nodes {
		if i == m.epNode { continue }
		glog.Infof("Adding %s to %s", n.HostName, epnode.HostName)
		if err := epnode.AddNode(n, n.Services); err != nil {
			if strings.Contains(err.Error(), "Prepare join failed. Got HTTP status 500 from REST call") {
				time.Sleep(5*time.Second)
				glog.Infof("Adding %s to %s again", n.HostName, epnode.HostName)
				err = epnode.AddNode(n, n.Services)
			}
			if err != nil {
				return "", err
			}
		}
	}

	// in case rebalance fails, just try one more time
	numRetry := 2
	for i := 0 ; i < numRetry; i++ {
		if err := epnode.Rebalance(nil, nil, nil); err != nil { return "", err }
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
		if err = m.SetupBucket(m.Config.Bucket.Name, m.Config.Bucket.Type, m.Config.Bucket.Password); err != nil {
			return "", err
		}
	}

	return fmt.Sprintf("http://%s:%s", epnode.HostName, epnode.Port), nil
}

func getVersion (node *Node) (*VersionTuple, error) {
	var refInfo RefInfo
	node.Update(false)
	info, err := node.GetInfo()
	if err != nil { return nil, err }

	err = json.Unmarshal([]byte(info), &refInfo)
	if err != nil { return nil, err }

	version := refInfo.ClusterVersion

	parsed := strings.Split(version, ".")
	if len(parsed) != 3 {
		return nil, errors.New("Unable to parse server version")
	}
	major, _ := strconv.Atoi(parsed[0])
	minor, _ := strconv.Atoi(parsed[1])
	patch, _ := strconv.Atoi(parsed[2])
	return &VersionTuple {
		Major: major,
		Minor: minor,
		Patch: patch,
	}, nil
}

func (m *Manager) PollCompressionMode(bucket, mode string) error {
	epnode := m.Nodes[m.epNode]
	return epnode.PollCompressionMode(bucket, mode)
}

func getEpNode (force bool, nodes []*Node) (*Node, error) {
	// select epnode (entry point node)
	var epnode *Node
	for _, n := range nodes {
		n.Update(force) // get "nodes" array from the response of /pools/nodes
		membership, err := n.Membership()
		if err != nil { return nil, err }
		if membership == Active {
			epnode = n
			break
		}
	}
	if epnode == nil {
		return nil, errors.New("Could not find active nodes")
	}
	return epnode, nil
}

func getFtsNode (force bool, nodes []*Node) (*Node, error) {
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
		return nil, errors.New("Could not find "+service+" nodes")
	}
	return svcNode, nil
}

func getN1qlNode (force bool, nodes []*Node) (*Node, error) {
	return getServiceNode(force, "n1ql", nodes)
}

func clearSingleCluster(nodes []*Node) error {

	epnode, err := getEpNode(true, nodes)

	buckets, err := epnode.GetBuckets()
	if err != nil { return err }

	for _, b := range *buckets {
		err = epnode.DeleteBucket(b.Name)
		if err != nil { return err }
	}

	// Fail over and Eject
	err = epnode.FailOverAndEjectAll(&helper.Cred{
		Hostname: epnode.HostName,
		Port: helper.RestPort,
		Username: RestUsername,
		Password: RestPassword,
	})
	if err != nil { return err }

	// reset master node

	glog.Infof("Reset the master node")
	cmd := "curl -d 'gen_server:cast(ns_cluster, leave).' -u "
	cmd += RestUsername + ":" + RestPassword
	cmd += " http://localhost:8091/diag/eval";
	var stdoutBuf, stderrBuf bytes.Buffer
	err = epnode.RunSsh(&stdoutBuf, &stderrBuf, cmd)

	// block till reset is done
	buff := make([]byte, 1024)
	for {
		n, err := stdoutBuf.Read(buff)
		glog.Infof("%q", buff[:n])
		if err == io.EOF { break }
	}
	return err
}

func (m *Manager) CreateUser(cred *helper.UserOption) error {
	epNode, err := getEpNode(false, m.Nodes)
	if err != nil { return err }
	if err = epNode.CreateUser(cred); err != nil { return err }
	return nil
}

func (m *Manager) CreateFtsIndex(name, bucketType, bucketName string) error {
	ftsNode, err := getFtsNode(false, m.Nodes)
	if err != nil { return err }
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
	if err != nil { return err }
	if err = epNode.NetworkReset(); err != nil {
		return err
	}
	return nil
}

func (m *Manager) NetworkDelay() error {
	epNode, err := getEpNode(false, m.Nodes)
	if err != nil { return err }
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
	if err != nil { return err }
	if err := n1qlNode.CreateN1qlIndex(name, fields, bucket); err != nil { return err}
	return nil
}

func (m *Manager) ChangeBucketCompression(bucket, mode string) error {
	if err := m.Nodes[m.epNode].ChangeBucketCompression(bucket, mode); err != nil { return err }
	return m.Nodes[m.epNode].WaitForBucketReady()
}

func (m *Manager) SetupBucket(bucketName, bucketType, bucketPassword string) error {
	var bType string
	switch bucketType {
		case "memcached": bType = helper.BucketMemcached
		case "ephemeral": bType = helper.BucketEphemeral
		default: bType = helper.BucketCouchbase
	}
	bc := Bucket {
		Name: bucketName,
		Type: bType,
		RamQuotaMB: "256",
		ReplicaCount: 1,
		EphEvictionPolicy: "noEviction",
	}
	if err := m.Nodes[m.epNode].CreateBucket(&bc); err != nil { return err }

	return m.Nodes[m.epNode].WaitForBucketReady()

}

func getNodes(ini []string) []*Node {

	var nodes []*Node
	for _, spec := range ini {
		nodeInfo := strings.Split(spec, ":")
		host := nodeInfo[0]
		port := nodeInfo[1]
		version := nodeInfo[2]
		services := nodeInfo[3]
		nodes = append(nodes, fromSpec(host, port, version, services))
	}

	return nodes
}

func fromSpec(host, port, version, services string) *Node {

	nPort := 8091
	if len(port) > 0 {
		num, err := strconv.Atoi(port)
		if err != nil { panic (err)}
		nPort = num
	}
	nodeHost := &Node {
		HostName: host,
		Port: strconv.Itoa(nPort),
		SshLogin: &helper.Cred { Username: "root", Password: "couchbase", Hostname: host, Port: 22 },
		RestLogin: &helper.Cred { Username: RestUsername, Password: RestPassword, Hostname: host, Port: nPort },
		N1qlLogin: &helper.Cred { Username: RestUsername, Password: RestPassword, Hostname: host, Port: 8093 },
		FtsLogin: &helper.Cred { Username: RestUsername, Password: RestPassword, Hostname: host, Port: 8094 },
		Version: version,
		Services: services,
	}

	return nodeHost

}

func parse(iniFileName string) ([]string, error) {

	file, err := os.Open(iniFileName)

	if err != nil { return nil, err }
	defer file.Close()

	scanner := bufio.NewScanner(file)
	var parsed []string
	// currently we parse only 'node'
	for scanner.Scan() {
		line := scanner.Text()
		if line[0] == '#' { continue }
		lineSlice := strings.Split(strings.TrimSpace(line), "=")
		if len(lineSlice) == 2 && lineSlice[0] == "node" {
			parsed = append(parsed, lineSlice[1])
		}
	}
	if err := scanner.Err(); err != nil { return nil, err}
	return parsed, nil
}
