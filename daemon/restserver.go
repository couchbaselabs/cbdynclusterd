package daemon

import (
	"context"
	"encoding/json"
	"errors"
	"github.com/couchbaselabs/cbdynclusterd/cluster"
	"github.com/couchbaselabs/cbdynclusterd/dyncontext"
	"github.com/couchbaselabs/cbdynclusterd/service"
	"github.com/couchbaselabs/cbdynclusterd/service/docker"
	"github.com/couchbaselabs/cbdynclusterd/store"
	"log"
	"net/http"
	"net/url"
	"strconv"
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

func jsonifyNode(node *cluster.Node) NodeJSON {
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

func UnjsonifyNode(jsonNode *NodeJSON) *cluster.Node {
	return &cluster.Node{
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

func jsonifyCluster(cluster *cluster.Cluster) ClusterJSON {
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

	return dyncontext.NewContext(r.Context(), user, ignoreOwnership), nil
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

func (d *daemon) HttpRoot(w http.ResponseWriter, r *http.Request) {
	w.Write([]byte("This is the cbdyncluster daemon!\n"))
}

type GetClustersJSON []ClusterJSON

func (d *daemon) HttpGetClusters(w http.ResponseWriter, r *http.Request) {
	reqCtx, err := getHttpContext(r)
	if err != nil {
		writeJSONError(w, err)
		return
	}

	clusters, err := d.getAllClusters(reqCtx)
	if err != nil {
		writeJSONError(w, err)
		return
	}

	jsonClusters := make(GetClustersJSON, 0)

	for _, c := range clusters {
		jsonCluster := jsonifyCluster(c)
		jsonClusters = append(jsonClusters, jsonCluster)
	}

	writeJsonResponse(w, jsonClusters)
}

type CreateClusterNodeJSON struct {
	Name                string `json:"name"`
	Platform            string `json:"platform"`
	ServerVersion       string `json:"server_version"`
	UseCommunityEdition bool   `json:"community_edition"`
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

func (d *daemon) HttpCreateCluster(w http.ResponseWriter, r *http.Request) {
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

	timeout := 1 * time.Hour

	if reqData.Timeout != "" {
		clusterTimeout, err := time.ParseDuration(reqData.Timeout)
		if err != nil {
			writeJSONError(w, err)
			return
		}

		timeout = clusterTimeout
	}

	if timeout < 0 {
		writeJSONError(w, errors.New("must specify a valid timeout for the cluster"))
		return
	}
	if timeout > 2*7*24*time.Hour {
		writeJSONError(w, errors.New("cannot allocate clusters for longer than 2 weeks"))
		return
	}
	clusterOpts := docker.AllocateClusterOptions{
		Deadline: time.Now().Add(timeout),
	}

	for _, node := range reqData.Nodes {
		nodeOpts := docker.CreateNodeOptions{
			Name:                node.Name,
			Platform:            node.Platform,
			ServerVersion:       node.ServerVersion,
			UseCommunityEdition: node.UseCommunityEdition,
		}
		clusterOpts.Nodes = append(clusterOpts.Nodes, nodeOpts)
	}

	clusterID, err := d.dockerService.AllocateCluster(reqCtx, clusterOpts)
	if err != nil {
		writeJSONError(w, err)
		return
	}

	meta := store.ClusterMeta{
		Owner:   dyncontext.ContextUser(reqCtx),
		Timeout: clusterOpts.Deadline,
	}
	if err := d.metaStore.CreateClusterMeta(clusterID, meta); err != nil {
		writeJSONError(w, err)
		return
	}

	newClusterJson := NewClusterJSON{
		ID: clusterID,
	}
	writeJsonResponse(w, newClusterJson)
}

type GetClusterJSON ClusterJSON

func (d *daemon) HttpGetCluster(w http.ResponseWriter, r *http.Request) {
	reqCtx, err := getHttpContext(r)
	if err != nil {
		writeJSONError(w, err)
		return
	}

	clusterID := mux.Vars(r)["cluster_id"]

	c, err := d.dockerService.GetCluster(reqCtx, clusterID)
	if err != nil {
		writeJSONError(w, err)
		return
	}

	jsonCluster := jsonifyCluster(c)

	writeJsonResponse(w, jsonCluster)
}

type UpdateClusterJSON struct {
	Timeout string `json:"timeout"`
}

func (d *daemon) HttpGetDockerHost(w http.ResponseWriter, r *http.Request) {
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

func (d *daemon) HttpSetupCluster(w http.ResponseWriter, r *http.Request) {
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

	c, err := d.dockerService.GetCluster(reqCtx, clusterID)
	if err != nil {
		writeJSONError(w, err)
		return
	}
	if len(c.Nodes) != len(reqData.Services) {
		writeJSONError(w, errors.New("services does not map to number of nodes"))
		return
	}

	epnode, err := d.dockerService.SetupCluster(&service.ClusterSetupOptions{
		Nodes:               c.Nodes,
		Services:            reqData.Services,
		UseHostname:         reqData.UseHostname,
		UseIpv6:             reqData.UseIpv6,
		MemoryQuota:         strconv.Itoa(reqData.RamQuota),
		User:                reqData.User,
		StorageMode:         reqData.StorageMode,
		Bucket:              reqData.Bucket,
		UseDeveloperPreview: reqData.UseDeveloperPreview,
	})
	if err != nil {
		writeJSONError(w, err)
		return
	}

	c.EntryPoint = epnode

	jsonCluster := jsonifyCluster(c)
	writeJsonResponse(w, jsonCluster)
	return
}

func (d *daemon) HttpUpdateCluster(w http.ResponseWriter, r *http.Request) {
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

		d.refreshCluster(reqCtx, clusterID, newTimeout)

		w.WriteHeader(200)
		return
	}

	writeJSONError(w, errors.New("not sure what you wanted to do"))
}

func (d *daemon) HttpDeleteCluster(w http.ResponseWriter, r *http.Request) {
	reqCtx, err := getHttpContext(r)
	if err != nil {
		writeJSONError(w, err)
		return
	}

	clusterID := mux.Vars(r)["cluster_id"]

	err = d.dockerService.KillCluster(reqCtx, clusterID)
	if err != nil {
		writeJSONError(w, err)
		return
	}

	w.WriteHeader(200)
}

type AddBucketJSON struct {
	Name           string `json:"name"`
	StorageMode    string `json:"storage_mode"`
	RamQuota       int    `json:"ram_quota"`
	UseHostname    bool   `json:"use_hostname"`
	ReplicaCount   int    `json:"replica_count"`
	BucketType     string `json:"bucket_type"`
	EvictionPolicy string `json:"eviction_policy"`
}

func (d *daemon) HttpAddBucket(w http.ResponseWriter, r *http.Request) {
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

	err = d.dockerService.AddBucket(reqCtx, clusterID, service.AddBucketOptions{
		Name:           reqData.Name,
		StorageMode:    reqData.StorageMode,
		RamQuota:       reqData.RamQuota,
		UseHostname:    reqData.UseHostname,
		ReplicaCount:   reqData.ReplicaCount,
		BucketType:     reqData.BucketType,
		EvictionPolicy: reqData.EvictionPolicy,
	})
	if err != nil {
		writeJSONError(w, err)
		return
	}

	w.WriteHeader(200)
}

type AddSampleBucketJSON struct {
	SampleBucket string `json:"sample_bucket"`
	UseHostname  bool   `json:"use_hostname"`
}

func (d *daemon) HttpAddSampleBucket(w http.ResponseWriter, r *http.Request) {
	reqCtx, err := getHttpContext(r)
	if err != nil {
		writeJSONError(w, err)
		return
	}

	clusterID := mux.Vars(r)["cluster_id"]

	var reqData AddSampleBucketJSON
	err = readJsonRequest(r, &reqData)
	if err != nil {
		writeJSONError(w, err)
		return
	}

	err = d.dockerService.AddSampleBucket(reqCtx, clusterID, service.AddSampleOptions{
		SampleBucket: reqData.SampleBucket,
		UseHostname:  reqData.UseHostname,
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

func (d *daemon) HttpAddCollection(w http.ResponseWriter, r *http.Request) {
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

	err = d.dockerService.AddCollection(reqCtx, clusterID, service.AddCollectionOptions{
		Name:        reqData.Name,
		ScopeName:   reqData.ScopeName,
		BucketName:  reqData.BucketName,
		UseHostname: reqData.UseHostname,
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

func (d *daemon) HttpSetupClientCertAuth(w http.ResponseWriter, r *http.Request) {
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

	c, err := d.dockerService.GetCluster(reqCtx, clusterID)
	if err != nil {
		writeJSONError(w, err)
		return
	}

	certData, err := d.dockerService.SetupCertAuth(service.SetupClientCertAuthOptions{
		Nodes:     c.Nodes,
		UserName:  reqData.UserName,
		UserEmail: reqData.UserEmail,
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
	ServerVersion       string `json:"server_version"`
	UseCommunityEdition bool   `json:"community_edition"`
}

type BuildImageResponseJSON struct {
	ImageName string `json:"image_name"`
}

func (d *daemon) HttpBuildImage(w http.ResponseWriter, r *http.Request) {
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

	image, err := d.dockerService.EnsureImageExists(reqCtx, reqData.ServerVersion, reqData.UseCommunityEdition)
	if err != nil {
		writeJSONError(w, err)
		return
	}

	imageJSON := BuildImageResponseJSON{
		ImageName: image,
	}
	writeJsonResponse(w, imageJSON)
}

func (d *daemon) createRESTRouter() *mux.Router {
	r := mux.NewRouter()
	r.HandleFunc("/", d.HttpRoot)
	r.HandleFunc("/docker-host", d.HttpGetDockerHost).Methods("GET")
	r.HandleFunc("/version", HttpGetVersion).Methods("GET")
	r.HandleFunc("/clusters", d.HttpGetClusters).Methods("GET")
	r.HandleFunc("/clusters", d.HttpCreateCluster).Methods("POST")
	r.HandleFunc("/cluster/{cluster_id}", d.HttpGetCluster).Methods("GET")
	r.HandleFunc("/cluster/{cluster_id}", d.HttpUpdateCluster).Methods("PUT")
	r.HandleFunc("/cluster/{cluster_id}/setup", d.HttpSetupCluster).Methods("POST")
	r.HandleFunc("/cluster/{cluster_id}", d.HttpDeleteCluster).Methods("DELETE")
	r.HandleFunc("/cluster/{cluster_id}/add-bucket", d.HttpAddBucket).Methods("POST")
	r.HandleFunc("/cluster/{cluster_id}/add-sample-bucket", d.HttpAddSampleBucket).Methods("POST")
	r.HandleFunc("/cluster/{cluster_id}/add-collection", d.HttpAddCollection).Methods("POST")
	r.HandleFunc("/cluster/{cluster_id}/setup-cert-auth", d.HttpSetupClientCertAuth).Methods("POST")
	r.HandleFunc("/images", d.HttpBuildImage).Methods("POST")
	return r
}
