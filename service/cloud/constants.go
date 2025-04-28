package cloud

const (
	// public API
	deleteClusterPath  = "/v4/organizations/%s/projects/%s/clusters/%s"
	getClusterPath     = "/v4/organizations/%s/projects/%s/clusters/%s"
	getAllClustersPath = "/v4/organizations/%s/projects/%s/clusters"
	// TODO: Use public API when AV-27634 fixed
	// createUserPath     = "/v3/clusters/%s/users"
	clustersHealthPath = "/v3/clusters/%s/health" // TODO: Update to v4 API; v3 is no longer supported
	// internal API
	internalBasePath = "/v2/organizations/%s/projects/%s/clusters/%s"
	// Need to use /deploy to use custom image
	createClusterPath   = "/v2/organizations/%s/clusters/deploy"
	createBucketPath    = internalBasePath + "/buckets"
	addIPPath           = internalBasePath + "/allowlists-bulk"
	addSampleBucketPath = internalBasePath + "/buckets/samples"
	getNodesPath        = internalBasePath + "/nodes"
	sessionsPath        = "/sessions"
	createUserPath      = internalBasePath + "/users"

	clusterHealthy          = "healthy"
	clusterDeleting         = "destroying"
	clusterDeploying        = "deploying"
	clusterDegraded         = "degraded"
	clusterDraft            = "draft"
	clusterDeploymentFailed = "deploymentFailed"
)
