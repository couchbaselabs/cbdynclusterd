package cluster

import "time"

type Cluster struct {
	ID         string
	Creator    string
	Owner      string
	Timeout    time.Time
	Nodes      []*Node
	EntryPoint string
}
