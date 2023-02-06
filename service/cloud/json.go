package cloud

type getAllClustersClusterJSON struct {
	ID   string `json:"id"`
	Name string `json:"name"`
}

type getAllClustersJSON struct {
	Data struct {
		Items []getAllClustersClusterJSON `json:"items"`
	} `json:"data"`
}

type getClusterJSONVersion struct {
	Name string `json:"name"`
}

type getClusterJSON struct {
	ID           string                `json:"id"`
	ProjectID    string                `json:"projectId"`
	Status       string                `json:"status"`
	Name         string                `json:"name"`
	Version      getClusterJSONVersion `json:"version"`
	EndpointsSRV string                `json:"endpointsSrv"`
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

type DiskType string

const (
	DiskTypeGP3   DiskType = "gp3"
	DiskTypeIO2   DiskType = "io2"
	DiskTypePDSSD DiskType = "pd-ssd"
)

var defaultRegionAWS = "us-east-2"
var defaultComputeAWS = Instance{
	Type: "m5.xlarge",
}
var defaultProvider = ProviderHostedAWS
var defaultSingleAZ = true
var defaultComputeGCP = Instance{
	Type: "n2-standard-4",
}
var defaultRegionGCP = "us-east1"
var defaultDiskeGCP = Disk{
	Type:     DiskTypePDSSD,
	SizeInGb: 50,
}
var defaultAWSIOPS = 3000
var defaultDiskAWS = Disk{
	Type:     DiskTypeGP3,
	IOPS:     &defaultAWSIOPS,
	SizeInGb: 50,
}

type SupportPackage string

const (
	SupportPackageDeveloperPro SupportPackage = "developerPro"
)

var defaultSupportPackage = SupportPackageDeveloperPro
var defaultSupportTimezone = ""

var defaultAWS = awsServerJSON{
	InstanceSize: "m5.xlarge",
	EbsSizeGib:   50,
}

type Provider string

const (
	ProviderHostedAWS Provider = "hostedAWS"
	ProviderAzure     Provider = "azure"
	ProviderHostedGCP Provider = "hostedGCP"
)

type V3PlaceHosted struct {
	Provider Provider `json:"provider"`
	Region   string   `json:"region"`
	CIDR     string   `json:"CIDR"`
}

type V3Place struct {
	SingleAZ bool          `json:"singleAZ"`
	Hosted   V3PlaceHosted `json:"hosted"`
}

type V3Environment string

const (
	V3EnvironmentHosted V3Environment = "hosted"
	V3EnvironmentVPC    V3Environment = "vpc"
)

type Override struct {
	Token  string `json:"token"`
	Image  string `json:"image"`
	Server string `json:"server"`
}

type Services []Service

type Service struct {
	Type string `json:"type"`
}

type Instance struct {
	Type       string `json:"type"`
	CPU        int    `json:"cpu"`
	MemoryInGb int    `json:"memoryInGb"`
}

type Disk struct {
	Type     DiskType `json:"type"`
	SizeInGb int      `json:"sizeInGb"`
	IOPS     *int     `json:"iops,omitempty"`
}

type Spec struct {
	Count    uint32   `json:"count"`
	Services Services `json:"services"`
	Compute  Instance `json:"compute"`
	Disk     Disk     `json:"disk"`
}

type setupClusterJson struct {
	CIDR        string         `json:"cidr"`
	Name        string         `json:"name"`
	Description string         `json:"description"`
	Override    *Override      `json:"overRide,omitempty"`
	ProjectID   string         `json:"projectId"`
	Provider    Provider       `json:"provider"`
	Region      string         `json:"region"`
	SingleAZ    bool           `json:"singleAZ"`
	Server      string         `json:"server,omitempty"`
	Specs       []Spec         `json:"specs"`
	Package     SupportPackage `json:"package"`
}

type V3BucketRole string

const (
	V3BucketRoleDataReader V3BucketRole = "data_reader"
	V3BucketRoleDataWriter V3BucketRole = "data_writer"
)

type ScopePermission struct {
	Name string `json:"name"`
}

type BucketPermission struct {
	Name   string            `json:"name"`
	Scopes []ScopePermission `json:"scopes,omitempty"`
}

type Permissions struct {
	Buckets []BucketPermission `json:"buckets,omitempty"`
}

type ReadWritePermissions struct {
	DataReader *Permissions `json:"data_reader"`
	DataWriter *Permissions `json:"data_writer"`
}

type databaseUserJSON struct {
	Name        string               `json:"name"`
	Password    string               `json:"password"`
	Permissions ReadWritePermissions `json:"permissions"`
}

// TODO: Use public API when AV-27634 fixed

// type databaseUserJSON struct {
// 	Username         string       `json:"username"`
// 	Password         string       `json:"password"`
// 	AllBucketsAccess V3BucketRole `json:"allBucketsAccess"`
// }

type bucketSpecJSON struct {
	Name              string `json:"name"`
	MemoryQuota       int    `json:"memoryAllocationInMb"`
	Replicas          int    `json:"replicas"`
	ConflicResolution string `json:"bucketConflictResolution"`
	DurabilityLevel   string `json:"durabilityLevel"`
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

type sessionsResponse struct {
	Jwt string `json:"jwt"`
}

type allowListJSON struct {
	CIDR    string `json:"cidr"`
	Comment string `json:"comment"`
}

type allowListBulkJSON struct {
	Create []allowListJSON `json:"create"`
}

type addSampleBucketJSON struct {
	Name string `json:"name"`
}

type getNodesJson struct {
	Data []struct {
		Data struct {
			Hostname string `json:"hostname"`
			ID       string `json:"id"`
		} `json:"data"`
	} `json:"data"`
}
