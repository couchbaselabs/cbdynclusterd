package daemon

import (
	"context"
	"github.com/couchbaselabs/cbdynclusterd/dyncontext"
	"github.com/couchbaselabs/cbdynclusterd/service"
	"github.com/couchbaselabs/cbdynclusterd/store"
	"log"
	"time"
)

func (d *daemon) refreshCluster(ctx context.Context, clusterID string, newTimeout time.Duration) error {
	log.Printf("Refreshing cluster %s (requested by: %s)", clusterID, dyncontext.ContextUser(ctx))

	newMeta := store.ClusterMeta{
		Owner:   dyncontext.ContextUser(ctx),
		Timeout: time.Now().Add(newTimeout),
	}

	meta, err := d.metaStore.GetClusterMeta(clusterID)
	if err != nil {
		// We don't seem to know anything about this so let's bail out.
		return err
	}

	newMeta.Platform = meta.Platform

	var s service.ClusterService
	if newMeta.Platform == store.ClusterPlatformCloud {
		s = d.cloudService
	} else if newMeta.Platform == store.ClusterPlatformDocker {
		s = d.dockerService
	} else if newMeta.Platform == store.ClusterPlatformEC2 {
		s = d.ec2Service
	} else {
		log.Printf("Cluster found with no platform, assuming docker: %s", clusterID)
		s = d.dockerService
		newMeta.Platform = store.ClusterPlatformDocker
	}

	// Check the cluster actually exists
	_, err = s.GetCluster(ctx, clusterID)
	if err != nil {
		return err
	}

	return d.metaStore.UpdateClusterMeta(clusterID, func(meta store.ClusterMeta) (store.ClusterMeta, error) {
		meta.Owner = newMeta.Owner
		if meta.Timeout.Before(newMeta.Timeout) {
			meta.Timeout = newMeta.Timeout
		}
		return meta, nil
	})
}
