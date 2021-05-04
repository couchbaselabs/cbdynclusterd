package cloud

const (
	createClusterPath  = "/v2/clusters"
	deleteClusterPath  = "/v2/clusters/"
	getClusterPath     = "/v2/clusters/"
	getAllClustersPath = "/v2/clusters"
	createBucketPath   = "/v2/clusters/%s/buckets"
	createUserPath     = "/v2/clusters/%s/users"
	addIPPath          = "/v2/clusters/%s/allowlist"
	deleteBucketPath   = "/v2/clusters/%s/buckets"
	clustersHealthPath = "/v2/clusters/%s/health"

	clusterReady     = "ready"
	clusterDeleting  = "destroying"
	clusterDeploying = "deploying"
)
