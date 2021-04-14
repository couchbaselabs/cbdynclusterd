package docker

import (
	"time"
)

type AllocateClusterOptions struct {
	Deadline time.Time
	Nodes    []CreateNodeOptions
}
