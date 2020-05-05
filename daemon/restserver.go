package daemon

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"log"
	"net/http"
	"net/url"
	"strings"
	"time"

	"github.com/couchbaselabs/cbdynclusterd/helper"
	"github.com/gorilla/mux"
)

var Version string

type ErrorJSON struct {
	Error struct {
		Message string `json:"message"`
	} `json:"error,omitempty"`
}

func jsonifyError(err error) ErrorJSON {
	jsonErr := ErrorJSON{}
	jsonErr.Error.Message = err.Error()
	return jsonErr
}

type RefreshJSON struct {
	Timeout string `json:"timeout"`
}

type NodeJSON struct {
	ID                   string `json:"id"`
	ContainerName        string `json:"container_name"`
	State                string `json:"state"`
	Name                 string `json:"name"`
	InitialServerVersion string `json:"initial_server_version"`
	IPv4Address          string `json:"ipv4_address"`
	IPv6Address          string `json:"ipv6_address"`
}

func jsonifyNode(node *Node) NodeJSON {
	return NodeJSON{
		ID:                   node.ContainerID,
		ContainerName:        node.ContainerName,
		State:                node.State,
		Name:                 node.Name,
		InitialServerVersion: node.InitialServerVersion,
		IPv4Address:          node.IPv4Address,
		IPv6Address:          node.IPv6Address,
	}
}

func UnjsonifyNode(jsonNode *NodeJSON) *Node {
	return &Node{
		ContainerID:          jsonNode.ID,
		ContainerName:        jsonNode.ContainerName,
		State:                jsonNode.State,
		Name:                 jsonNode.Name,
		InitialServerVersion: jsonNode.InitialServerVersion,
		IPv4Address:          jsonNode.IPv4Address,
		IPv6Address:          jsonNode.IPv6Address,
	}
}

type DockerHostJSON struct {
	Hostname string `json:"hostname"`
	Port     string `json:"port"`
}

type VersionJSON struct {
	Version string `json:"version"`
}

type ClusterJSON struct {
	ID         string     `json:"id"`
	Creator    string     `json:"creator"`
	Owner      string     `json:"owner"`
	Timeout    string     `json:"timeout"`
	Nodes      []NodeJSON `json:"nodes"`
	EntryPoint string     `json:"entry"`
}

func jsonifyCluster(cluster *Cluster) ClusterJSON {
	jsonCluster := ClusterJSON{
		ID:         cluster.ID,
		Creator:    cluster.Creator,
		Owner:      cluster.Owner,
		Timeout:    cluster.Timeout.Format(time.RFC3339),
		EntryPoint: cluster.EntryPoint,
	}

	for _, node := range cluster.Nodes {
		jsonNode := jsonifyNode(node)
		jsonCluster.Nodes = append(jsonCluster.Nodes, jsonNode)
	}

	return jsonCluster
}

func UnjsonifyDockerHost(dockerHost *DockerHostJSON) (string, error) {
	if dockerHost == nil || dockerHost.Hostname == "" || dockerHost.Port == "" {
		return "", errors.New("Docker hostname or port is empty")
	}
	return fmt.Sprintf("%s:%s", dockerHost.Hostname, dockerHost.Port), nil
}

func UnjsonifyVersion(version *VersionJSON) (string, error) {
	if version == nil || version.Version == "" {
		return "", errors.New("cbdynclusterd version is empty")
	}
	return version.Version, nil
}

func UnjsonifyCluster(jsonCluster *ClusterJSON) (*Cluster, error) {
	cluster := &Cluster{}
	cluster.ID = jsonCluster.ID
	cluster.Creator = jsonCluster.Creator
	cluster.Owner = jsonCluster.Owner
	cluster.EntryPoint = jsonCluster.EntryPoint

	clusterTimeout, err := time.Parse(time.RFC3339, jsonCluster.Timeout)
	if err != nil {
		return nil, err
	}
	cluster.Timeout = clusterTimeout

	for _, jsonNode := range jsonCluster.Nodes {
		node := UnjsonifyNode(&jsonNode)
		cluster.Nodes = append(cluster.Nodes, node)
	}

	return cluster, nil
}

func getHttpContext(r *http.Request) (context.Context, error) {
	userHeader := r.Header.Get("cbdn-user")
	if userHeader == "" {
		return nil, errors.New("must specify a user")
	}
	if !strings.HasSuffix(userHeader, "@couchbase.com") {
		return nil, errors.New("your user must be your @couchbase.com email")
	}
	user := userHeader

	ignoreOwnership := false
	adminHeader := r.Header.Get("cbdn-admin")
	if adminHeader == "true" {
		ignoreOwnership = true
	}

	return NewContext(r.Context(), user, ignoreOwnership), nil
}

func writeJSONError(w http.ResponseWriter, err error) {
	jsonErr := jsonifyError(err)

	jsonBytes, err := json.Marshal(jsonErr)
	if err != nil {
		log.Printf("Failed to marshal error JSON: %s", err)
		w.WriteHeader(500)
		return
	}

	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(400)
	w.Write(jsonBytes)
}

func writeJsonResponse(w http.ResponseWriter, data interface{}) {
	jsonBytes, err := json.Marshal(data)
	if err != nil {
		log.Printf("Failed to marshal response JSON: %s", err)
		w.WriteHeader(500)
		return
	}

	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(200)
	w.Write(jsonBytes)
}

func readJsonRequest(r *http.Request, data interface{}) error {
	jsonDec := json.NewDecoder(r.Body)
	return jsonDec.Decode(data)
}

func HttpRoot(w http.ResponseWriter, r *http.Request) {
	w.Write([]byte("This is the cbdyncluster daemon!\n"))
}

type GetClustersJSON []ClusterJSON

func HttpGetClusters(w http.ResponseWriter, r *http.Request) {
	reqCtx, err := getHttpContext(r)
	if err != nil {
		writeJSONError(w, err)
		return
	}

	clusters, err := getAllClusters(reqCtx)
	if err != nil {
		writeJSONError(w, err)
		return
	}

	jsonClusters := make(GetClustersJSON, 0)

	for _, cluster := range clusters {
		jsonCluster := jsonifyCluster(cluster)
		jsonClusters = append(jsonClusters, jsonCluster)
	}

	writeJsonResponse(w, jsonClusters)
}

type CreateClusterNodeJSON struct {
	Name          string `json:"name"`
	Platform      string `json:"platform"`
	ServerVersion string `json:"server_version"`
}

type CreateClusterSetupJSON struct {
	Services            []string             `json:"services"`
	StorageMode         string               `json:"storage_mode"`
	RamQuota            int                  `json:"ram_quota"`
	UseHostname         bool                 `json:"use_hostname"`
	UseIpv6             bool                 `json:"use_ipv6"`
	Bucket              *helper.BucketOption `json:"bucket"`
	User                *helper.UserOption   `json:"user"`
	UseDeveloperPreview bool                 `json:"developer_preview"`
}

type CreateClusterJSON struct {
	Timeout string                  `json:"timeout"`
	Nodes   []CreateClusterNodeJSON `json:"nodes"`
	Setup   CreateClusterNodeJSON   `json:"setup"`
}

type NewClusterJSON struct {
	ID string `json:"id"`
}

func HttpCreateCluster(w http.ResponseWriter, r *http.Request) {
	reqCtx, err := getHttpContext(r)
	if err != nil {
		writeJSONError(w, err)
		return
	}

	var reqData CreateClusterJSON
	err = readJsonRequest(r, &reqData)
	if err != nil {
		writeJSONError(w, err)
		return
	}

	clusterOpts := ClusterOptions{
		Timeout: 1 * time.Hour,
	}

	if reqData.Timeout != "" {
		clusterTimeout, err := time.ParseDuration(reqData.Timeout)
		if err != nil {
			writeJSONError(w, err)
			return
		}

		clusterOpts.Timeout = clusterTimeout
	}

	for _, node := range reqData.Nodes {
		nodeVersion, err := parseServerVersion(node.ServerVersion)
		if err != nil {
			writeJSONError(w, err)
			return
		}

		nodeOpts := NodeOptions{
			Name:          node.Name,
			Platform:      node.Platform,
			ServerVersion: node.ServerVersion,
			VersionInfo:   nodeVersion,
		}
		clusterOpts.Nodes = append(clusterOpts.Nodes, nodeOpts)
	}

	clusterID, err := allocateCluster(reqCtx, clusterOpts)
	if err != nil {
		writeJSONError(w, err)
		return
	}

	newClusterJson := NewClusterJSON{
		ID: clusterID,
	}
	writeJsonResponse(w, newClusterJson)
}

type GetClusterJSON ClusterJSON

func HttpGetCluster(w http.ResponseWriter, r *http.Request) {
	reqCtx, err := getHttpContext(r)
	if err != nil {
		writeJSONError(w, err)
		return
	}

	clusterID := mux.Vars(r)["cluster_id"]

	cluster, err := getCluster(reqCtx, clusterID)
	if err != nil {
		writeJSONError(w, err)
		return
	}

	jsonCluster := jsonifyCluster(cluster)

	writeJsonResponse(w, jsonCluster)
}

type UpdateClusterJSON struct {
	Timeout string `json:"timeout"`
}

func HttpGetDockerHost(w http.ResponseWriter, r *http.Request) {
	hostURI, err := url.Parse(dockerHost)
	if err != nil {
		writeJSONError(w, err)
		return
	}

	if hostURI.Scheme != "tcp" {
		writeJSONError(w, errors.New("docker is not configured via tcp and cannot return the docker host"))
		return
	}

	jsonResp := &DockerHostJSON{
		Hostname: hostURI.Hostname(),
		Port:     hostURI.Port(),
	}
	writeJsonResponse(w, jsonResp)
	return
}

func HttpGetVersion(w http.ResponseWriter, r *http.Request) {
	jsonResp := &VersionJSON{
		Version: Version,
	}
	writeJsonResponse(w, jsonResp)
	return
}

func HttpSetupCluster(w http.ResponseWriter, r *http.Request) {
	reqCtx, err := getHttpContext(r)
	if err != nil {
		writeJSONError(w, err)
		return
	}

	clusterID := mux.Vars(r)["cluster_id"]

	var reqData CreateClusterSetupJSON
	err = readJsonRequest(r, &reqData)
	if err != nil {
		writeJSONError(w, err)
		return
	}

	cluster, err := getCluster(reqCtx, clusterID)
	if err != nil {
		writeJSONError(w, err)
		return
	}
	if len(cluster.Nodes) != len(reqData.Services) {
		writeJSONError(w, errors.New("services does not map to number of nodes"))
		return
	}

	epnode, err := SetupCluster(&ClusterSetupOptions{
		Nodes: cluster.Nodes,
		Conf:  reqData,
	})
	if err != nil {
		writeJSONError(w, err)
		return
	}

	cluster.EntryPoint = epnode

	jsonCluster := jsonifyCluster(cluster)
	writeJsonResponse(w, jsonCluster)
	return
}

func HttpUpdateCluster(w http.ResponseWriter, r *http.Request) {
	reqCtx, err := getHttpContext(r)
	if err != nil {
		writeJSONError(w, err)
		return
	}

	clusterID := mux.Vars(r)["cluster_id"]

	var reqData UpdateClusterJSON
	err = readJsonRequest(r, &reqData)
	if err != nil {
		writeJSONError(w, err)
		return
	}

	if reqData.Timeout != "" {
		newTimeout, err := time.ParseDuration(reqData.Timeout)
		if err != nil {
			writeJSONError(w, err)
			return
		}

		refreshCluster(reqCtx, clusterID, newTimeout)

		w.WriteHeader(200)
		return
	}

	writeJSONError(w, errors.New("not sure what you wanted to do"))
}

func HttpDeleteCluster(w http.ResponseWriter, r *http.Request) {
	reqCtx, err := getHttpContext(r)
	if err != nil {
		writeJSONError(w, err)
		return
	}

	clusterID := mux.Vars(r)["cluster_id"]

	err = killCluster(reqCtx, clusterID)
	if err != nil {
		writeJSONError(w, err)
		return
	}

	w.WriteHeader(200)
}

type AddBucketJSON struct {
	Name         string `json:"name"`
	StorageMode  string `json:"storage_mode"`
	RamQuota     int    `json:"ram_quota"`
	UseHostname  bool   `json:"use_hostname"`
	ReplicaCount int    `json:"replica_count"`
	BucketType   string `json:"bucket_type"`
}

func HttpAddBucket(w http.ResponseWriter, r *http.Request) {
	reqCtx, err := getHttpContext(r)
	if err != nil {
		writeJSONError(w, err)
		return
	}

	clusterID := mux.Vars(r)["cluster_id"]

	var reqData AddBucketJSON
	err = readJsonRequest(r, &reqData)
	if err != nil {
		writeJSONError(w, err)
		return
	}

	err = addBucket(reqCtx, clusterID, AddBucketOptions{
		Conf: reqData,
	})
	if err != nil {
		writeJSONError(w, err)
		return
	}

	w.WriteHeader(200)
}

type AddCollectionJSON struct {
	Name        string `json:"name"`
	ScopeName   string `json:"scope_name"`
	BucketName  string `json:"bucket_name"`
	UseHostname bool   `json:"use_hostname"`
}

func HttpAddCollection(w http.ResponseWriter, r *http.Request) {
	reqCtx, err := getHttpContext(r)
	if err != nil {
		writeJSONError(w, err)
		return
	}

	clusterID := mux.Vars(r)["cluster_id"]

	var reqData AddCollectionJSON
	err = readJsonRequest(r, &reqData)
	if err != nil {
		writeJSONError(w, err)
		return
	}

	err = addCollection(reqCtx, clusterID, AddCollectionOptions{
		Conf: reqData,
	})
	if err != nil {
		writeJSONError(w, err)
		return
	}

	w.WriteHeader(200)
}

type SetupClientCertAuthJSON struct {
	UserName  string `json:"user"`
	UserEmail string `json:"email"`
}

type CertAuthResultJSON struct {
	CACert     []byte `json:"cacert"`
	ClientKey  []byte `json:"client_key"`
	ClientCert []byte `json:"client_cert"`
}

func HttpSetupClientCertAuth(w http.ResponseWriter, r *http.Request) {
	reqCtx, err := getHttpContext(r)
	if err != nil {
		writeJSONError(w, err)
		return
	}

	clusterID := mux.Vars(r)["cluster_id"]

	var reqData SetupClientCertAuthJSON
	err = readJsonRequest(r, &reqData)
	if err != nil {
		writeJSONError(w, err)
		return
	}

	cluster, err := getCluster(reqCtx, clusterID)
	if err != nil {
		writeJSONError(w, err)
		return
	}

	certData, err := SetupCertAuth(SetupClientCertAuthOptions{
		Nodes: cluster.Nodes,
		Conf:  reqData,
	})
	if err != nil {
		writeJSONError(w, err)
		return
	}

	writeJsonResponse(w, CertAuthResultJSON{
		CACert:     certData.CACert,
		ClientKey:  certData.ClientKey,
		ClientCert: certData.ClientCert,
	})
	return
}

type BuildImageJSON struct {
	ServerVersion string `json:"server_version"`
}

type BuildImageResponseJSON struct {
	ImageName string `json:"image_name"`
}

func HttpBuildImage(w http.ResponseWriter, r *http.Request) {
	reqCtx, err := getHttpContext(r)
	if err != nil {
		writeJSONError(w, err)
		return
	}

	var reqData BuildImageJSON
	err = readJsonRequest(r, &reqData)
	if err != nil {
		writeJSONError(w, err)
		return
	}

	nodeVersion, err := parseServerVersion(reqData.ServerVersion)
	if err != nil {
		writeJSONError(w, err)
		return
	}

	err = ensureImageExists(reqCtx, nodeVersion, "")
	if err != nil {
		writeJSONError(w, err)
		return
	}

	imageJSON := BuildImageResponseJSON{
		ImageName: nodeVersion.toImageName(),
	}
	writeJsonResponse(w, imageJSON)
}

func createRESTRouter() *mux.Router {
	r := mux.NewRouter()
	r.HandleFunc("/", HttpRoot)
	r.HandleFunc("/docker-host", HttpGetDockerHost).Methods("GET")
	r.HandleFunc("/version", HttpGetVersion).Methods("GET")
	r.HandleFunc("/clusters", HttpGetClusters).Methods("GET")
	r.HandleFunc("/clusters", HttpCreateCluster).Methods("POST")
	r.HandleFunc("/cluster/{cluster_id}", HttpGetCluster).Methods("GET")
	r.HandleFunc("/cluster/{cluster_id}", HttpUpdateCluster).Methods("PUT")
	r.HandleFunc("/cluster/{cluster_id}/setup", HttpSetupCluster).Methods("POST")
	r.HandleFunc("/cluster/{cluster_id}", HttpDeleteCluster).Methods("DELETE")
	r.HandleFunc("/cluster/{cluster_id}/add-bucket", HttpAddBucket).Methods("POST")
	r.HandleFunc("/cluster/{cluster_id}/add-collection", HttpAddCollection).Methods("POST")
	r.HandleFunc("/cluster/{cluster_id}/setup-cert-auth", HttpSetupClientCertAuth).Methods("POST")
	r.HandleFunc("/images", HttpBuildImage).Methods("POST")
	return r
}
