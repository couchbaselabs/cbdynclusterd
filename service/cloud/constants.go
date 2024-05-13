package cloud

const (
	// public API
	deleteClusterPath  = "/v3/clusters/"
	getClusterPath     = "/v3/clusters/"
	getAllClustersPath = "/v3/clusters"
	// TODO: Use public API when AV-27634 fixed
	// createUserPath     = "/v3/clusters/%s/users"
	clustersHealthPath = "/v3/clusters/%s/health"

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

	createColumnarPath       = "/v2/organizations/%s/projects/%s/instance"
	internalInstanceBasePath = "/v2/organizations/%s/projects/%s/instance/%s"

	addColumnarIPPath = internalInstanceBasePath + "/allowlists"

	clusterHealthy          = "healthy"
	clusterDeleting         = "destroying"
	clusterDeploying        = "deploying"
	clusterDegraded         = "degraded"
	clusterDraft            = "draft"
	clusterDeploymentFailed = "deploymentFailed"
)
