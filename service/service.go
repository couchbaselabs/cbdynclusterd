package service

import (
	"context"
	"github.com/couchbaselabs/cbdynclusterd/cluster"
)

type CertAuthResult struct {
	CACert     []byte
	ClientKey  []byte
	ClientCert []byte
}

type ClusterService interface {
	GetCluster(ctx context.Context, clusterID string) (*cluster.Cluster, error)
	GetAllClusters(ctx context.Context) ([]*cluster.Cluster, error)
	KillCluster(ctx context.Context, clusterID string) error
	KillAllClusters(ctx context.Context) error
	SetupCluster(opts *ClusterSetupOptions) (string, error)
	AddCollection(ctx context.Context, clusterID string, opts AddCollectionOptions) error
	SetupCertAuth(opts SetupClientCertAuthOptions) (*CertAuthResult, error)
	AddBucket(ctx context.Context, clusterID string, opts AddBucketOptions) error
	AddSampleBucket(ctx context.Context, clusterID string, opts AddSampleOptions) error
}
