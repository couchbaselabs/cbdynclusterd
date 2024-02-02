package service

import (
	"context"
	"errors"
	"time"

	"github.com/couchbaselabs/cbdynclusterd/cluster"
)

type CertAuthResult struct {
	CACert     []byte
	ClientKey  []byte
	ClientCert []byte
}

type CBCollectResult struct {
	Collections map[string][]byte
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
	ServerlessMode      bool
}

type ConnectContext struct {
	RestUsername string
	RestPassword string
	UseSecure    bool
	SshUsername  string
	SshPassword  string
	SshKeyPath   string
}

type ClusterService interface {
	GetCluster(ctx context.Context, clusterID string) (*cluster.Cluster, error)
	GetAllClusters(ctx context.Context) ([]*cluster.Cluster, error)
	KillCluster(ctx context.Context, clusterID string) error
	KillAllClusters(ctx context.Context) error
	AddCollection(ctx context.Context, clusterID string, opts AddCollectionOptions, connCtx ConnectContext) error
	SetupCertAuth(ctx context.Context, clusterID string, opts SetupClientCertAuthOptions, connCtx ConnectContext) (*CertAuthResult, error)
	AddBucket(ctx context.Context, clusterID string, opts AddBucketOptions, connCtx ConnectContext) error
	AddSampleBucket(ctx context.Context, clusterID string, opts AddSampleOptions, connCtx ConnectContext) error
	AddIP(ctx context.Context, clusterID, ip string) error
	AddUser(ctx context.Context, clusterID string, opts AddUserOptions, connCtx ConnectContext) error
	ConnString(ctx context.Context, clusterID string, useSSL bool, useSrv bool) (string, error)
	SetupClusterEncryption(ctx context.Context, clusterID string, opts SetupClusterEncryptionOptions, connCtx ConnectContext) error
	GetCertificate(ctx context.Context, clusterID string) (string, error)
}

type UnmanagedClusterService interface {
	ClusterService
	AllocateCluster(ctx context.Context, opts AllocateClusterOptions) error
	RunCBCollect(ctx context.Context, clusterID string) (*CBCollectResult, error)
}

var MaxCapacityError = errors.New("max capacity reached")
