package cluster

import "time"

type Cluster struct {
	ID         string
	Creator    string
	Status     string
	Owner      string
	Timeout    time.Time
	Nodes      []*Node
	EntryPoint string
}
