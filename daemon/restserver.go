package daemon

import (
	"context"
	"encoding/json"
	"errors"
	"log"
	"net/http"
	"strings"
	"time"

	"github.com/gorilla/mux"
)

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

type NodeJSON struct {
	ID                   string `json:"id"`
	State                string `json:"state"`
	Name                 string `json:"name"`
	InitialServerVersion string `json:"initial_server_version"`
	IPv4Address          string `json:"ipv4_address"`
	IPv6Address          string `json:"ipv6_address"`
}

func jsonifyNode(node *Node) NodeJSON {
	return NodeJSON{
		ID:                   node.ContainerID,
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
		State:                jsonNode.State,
		Name:                 jsonNode.Name,
		InitialServerVersion: jsonNode.InitialServerVersion,
		IPv4Address:          jsonNode.IPv4Address,
		IPv6Address:          jsonNode.IPv6Address,
	}
}

type ClusterJSON struct {
	ID      string     `json:"id"`
	Creator string     `json:"creator"`
	Owner   string     `json:"owner"`
	Timeout string     `json:"timeout"`
	Nodes   []NodeJSON `json:"nodes"`
}

func jsonifyCluster(cluster *Cluster) ClusterJSON {
	jsonCluster := ClusterJSON{
		ID:      cluster.ID,
		Creator: cluster.Creator,
		Owner:   cluster.Owner,
		Timeout: cluster.Timeout.Format(time.RFC3339),
	}

	for _, node := range cluster.Nodes {
		jsonNode := jsonifyNode(node)
		jsonCluster.Nodes = append(jsonCluster.Nodes, jsonNode)
	}

	return jsonCluster
}

func UnjsonifyCluster(jsonCluster *ClusterJSON) (*Cluster, error) {
	cluster := &Cluster{}
	cluster.ID = jsonCluster.ID
	cluster.Creator = jsonCluster.Creator
	cluster.Owner = jsonCluster.Owner

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

func createRESTRouter() *mux.Router {
	r := mux.NewRouter()
	r.HandleFunc("/", HttpRoot)
	r.HandleFunc("/clusters", HttpGetClusters).Methods("GET")
	r.HandleFunc("/clusters", HttpCreateCluster).Methods("POST")
	r.HandleFunc("/cluster/{cluster_id}", HttpGetCluster).Methods("GET")
	r.HandleFunc("/cluster/{cluster_id}", HttpUpdateCluster).Methods("PUT")
	r.HandleFunc("/cluster/{cluster_id}", HttpDeleteCluster).Methods("DELETE")
	return r
}
