package service

import (
	"context"
	"github.com/couchbaselabs/cbdynclusterd/cluster"
	"github.com/couchbaselabs/cbdynclusterd/helper"
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
	AddCollection(ctx context.Context, clusterID string, opts AddCollectionOptions) error
	SetupCertAuth(ctx context.Context, clusterID string, opts SetupClientCertAuthOptions) (*CertAuthResult, error)
	AddBucket(ctx context.Context, clusterID string, opts AddBucketOptions) error
	AddSampleBucket(ctx context.Context, clusterID string, opts AddSampleOptions) error
	AddIP(ctx context.Context, clusterID, ip string) error
	AddUser(ctx context.Context, clusterID string, user *helper.UserOption, bucket string) error
	ConnString(ctx context.Context, clusterID string, useSSL bool) (string, error)
}
