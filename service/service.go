package service

import (
	"context"
	"errors"
	"time"

	"github.com/couchbaselabs/cbdynclusterd/cluster"
	"github.com/couchbaselabs/cbdynclusterd/helper"
)

type CertAuthResult struct {
	CACert     []byte
	ClientKey  []byte
	ClientCert []byte
}

type AllocateClusterOptions struct {
	ClusterID string
	Deadline  time.Time
	Nodes     []CreateNodeOptions
}

type CreateNodeOptions struct {
	Name                string
	Platform            string
	ServerVersion       string
	UseCommunityEdition bool
	OS                  string
	Arch                string
}
type ClusterService interface {
	GetCluster(ctx context.Context, clusterID string) (*cluster.Cluster, error)
	GetAllClusters(ctx context.Context) ([]*cluster.Cluster, error)
	KillCluster(ctx context.Context, clusterID string) error
	KillAllClusters(ctx context.Context) error
	AddCollection(ctx context.Context, clusterID string, opts AddCollectionOptions) error
	SetupCertAuth(ctx context.Context, clusterID string, opts SetupClientCertAuthOptions) (*CertAuthResult, error)
	AddBucket(ctx context.Context, clusterID string, opts AddBucketOptions) error
	AddSampleBucket(ctx context.Context, clusterID string, opts AddSampleOptions) error
	AddIP(ctx context.Context, clusterID, ip string) error
	AddUser(ctx context.Context, clusterID string, user *helper.UserOption, bucket string) error
	ConnString(ctx context.Context, clusterID string, useSSL bool, useSrv bool) (string, error)
	SetupClusterEncryption(ctx context.Context, clusterID string, opts SetupClusterEncryptionOptions) error
}

type UnmanagedClusterService interface {
	AllocateCluster(ctx context.Context, opts AllocateClusterOptions) error
}

var MaxCapacityError = errors.New("max capacity reached")
