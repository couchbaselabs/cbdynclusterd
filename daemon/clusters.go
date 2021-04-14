package daemon

import (
	"context"
	"github.com/couchbaselabs/cbdynclusterd/dyncontext"
	"github.com/couchbaselabs/cbdynclusterd/store"
	"log"
	"time"
)

func (d *daemon) refreshCluster(ctx context.Context, clusterID string, newTimeout time.Duration) error {
	log.Printf("Refreshing cluster %s (requested by: %s)", clusterID, dyncontext.ContextUser(ctx))

	// Check the cluster actuall exists
	_, err := d.dockerService.GetCluster(ctx, clusterID)
	if err != nil {
		return err
	}

	newMeta := store.ClusterMeta{
		Owner:   dyncontext.ContextUser(ctx),
		Timeout: time.Now().Add(newTimeout),
	}

	_, err = d.metaStore.GetClusterMeta(clusterID)
	if err != nil {
		// If we failed to fetch the cluster metadata, just insert some instead
		return d.metaStore.CreateClusterMeta(clusterID, newMeta)
	}

	return d.metaStore.UpdateClusterMeta(clusterID, func(meta store.ClusterMeta) (store.ClusterMeta, error) {
		meta.Owner = newMeta.Owner
		if meta.Timeout.Before(newMeta.Timeout) {
			meta.Timeout = newMeta.Timeout
		}
		return meta, nil
	})
}
