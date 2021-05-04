package cloud

type getAllClustersClusterJSON struct {
	ID       string `json:"id"`
	Name     string `json:"name"`
	Status   string `json:"status"`
	Region   string `json:"region"`
	Provider string `json:"provider"`
}

type getAllClustersJSON struct {
	Data []getAllClustersClusterJSON `json:"data"`
}

type getClusterJSONVersion struct {
	Name string `json:"name"`
}

type getClusterJSON struct {
	CloudID      string                `json:"cloudID"`
	ID           string                `json:"id"`
	ProjectID    string                `json:"projectID"`
	Status       string                `json:"status"`
	Name         string                `json:"name"`
	Version      getClusterJSONVersion `json:"version"`
	EndpointsSRV string                `json:"endpointsSRV"`
	EndpointsURL []string              `json:"endpointsURL"`
}

type awsServerJSON struct {
	InstanceSize string `json:"instanceSize"`
	EbsSizeGib   int    `json:"ebsSizeGib"`
}

type nodeJson struct {
	Services []string      `json:"services"`
	Size     uint32        `json:"size"`
	AWS      awsServerJSON `json:"aws"`
}

type supportPackageJson struct {
	Type     string `json:"type"`
	Timezone string `json:"timezone"`
}

var defaultSupportPackage = supportPackageJson{
	Type:     "developerPro",
	Timezone: "PT",
}

var defaultAWS = awsServerJSON{
	InstanceSize: "m5.xlarge",
	EbsSizeGib:   100,
}

type setupClusterJson struct {
	Name           string             `json:"name"`
	CloudID        string             `json:"cloudId"`
	ProjectID      string             `json:"projectId"`
	Servers        []nodeJson         `json:"servers"`
	SupportPackage supportPackageJson `json:"supportPackage"`
	Version        string             `json:"version,omitempty"`
}

type databaseUserRoleJSON struct {
	BucketName string   `json:"name"`
	Roles      []string `json:"roles"`
}

type databaseUserJSON struct {
	Username string                 `json:"username"`
	Password string                 `json:"password"`
	Access   []databaseUserRoleJSON `json:"access"`
}

type bucketSpecJSON struct {
	Name        string `json:"name"`
	MemoryQuota int    `json:"memoryQuota"`
}

type bucketDeleteJSON struct {
	Name string `json:"name"`
}

type clusterHealthResponse struct {
	BucketStats struct {
		HealthStats    map[string]string `json:"healthStats"`
		Status         string            `json:"status"`
		TotalCount     int               `json:"totalCount"`
		UnhealthyCount int               `json:"unhealthyCount"`
	} `json:"bucketStats"`
}
