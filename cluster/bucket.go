package cluster

type Bucket struct {
	Type              string
	RamQuotaMB        string
	Name              string
	ReplicaCount      int
	EphEvictionPolicy string
	StorageBackend    string
	NumVBuckets       int
	Width             int
}
