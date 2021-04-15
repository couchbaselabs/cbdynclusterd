package daemon

import (
	"encoding/json"
	"log"
	"net/http"
	"time"

	"github.com/couchbaselabs/cbdynclusterd/cluster"
	"github.com/couchbaselabs/cbdynclusterd/helper"
)

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

func jsonifyError(err error) ErrorJSON {
	jsonErr := ErrorJSON{}
	jsonErr.Error.Message = err.Error()
	return jsonErr
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

type ErrorJSON struct {
	Error struct {
		Message string `json:"message"`
	} `json:"error,omitempty"`
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

type UpdateClusterJSON struct {
	Timeout string `json:"timeout"`
}

type AddBucketJSON struct {
	Name           string `json:"name"`
	StorageMode    string `json:"storage_mode"`
	RamQuota       int    `json:"ram_quota"`
	UseHostname    bool   `json:"use_hostname"`
	ReplicaCount   int    `json:"replica_count"`
	BucketType     string `json:"bucket_type"`
	EvictionPolicy string `json:"eviction_policy"`
	StorageBackend string `json:"storage_backend"`
}

type AddSampleBucketJSON struct {
	SampleBucket string `json:"sample_bucket"`
	UseHostname  bool   `json:"use_hostname"`
}

type AddCollectionJSON struct {
	Name        string `json:"name"`
	ScopeName   string `json:"scope_name"`
	BucketName  string `json:"bucket_name"`
	UseHostname bool   `json:"use_hostname"`
}

type SetupClientCertAuthJSON struct {
	UserName  string `json:"user"`
	UserEmail string `json:"email"`
	NumRoots  int    `json:"num_roots"`
}

type CertAuthResultJSON struct {
	CACert     []byte `json:"cacert"`
	ClientKey  []byte `json:"client_key"`
	ClientCert []byte `json:"client_cert"`
}

type BuildImageJSON struct {
	ServerVersion       string `json:"server_version"`
	UseCommunityEdition bool   `json:"community_edition"`
}

type BuildImageResponseJSON struct {
	ImageName string `json:"image_name"`
}