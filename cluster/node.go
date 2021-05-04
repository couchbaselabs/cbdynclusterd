package cluster

type Node struct {
	ContainerID          string
	ContainerName        string
	State                string
	Name                 string
	InitialServerVersion string
	IPv4Address          string
	IPv6Address          string
}
