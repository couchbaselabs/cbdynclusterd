package daemon

import (
	"context"
	"log"
	"net/http"
	"os"
	"os/signal"
	"time"

	"github.com/docker/docker/api/types"
	"github.com/docker/docker/client"
)

var docker *client.Client
var metaStore *MetaDataStore
var systemCtx context.Context
var dockerRegistry = "dockerhub.build.couchbase.com" // TODO: get this from a config

func openMeta() error {
	meta := &MetaDataStore{}

	err := meta.Open("./data")
	if err != nil {
		return err
	}

	metaStore = meta
	return nil
}

func connectDocker() error {
	var clientOpts []func(*client.Client) error
	clientOpts = append(clientOpts, client.FromEnv)
	clientOpts = append(clientOpts, client.WithHost("http://172.23.104.43:2376")) // TODO: get this from a config
	clientOpts = append(clientOpts, client.WithVersion("1.38"))

	cli, err := client.NewClientWithOpts(clientOpts...)
	if err != nil {
		return err
	}

	docker = cli
	return nil
}

func connectRegistry(ctx context.Context, uri string) error {
	_, err := docker.RegistryLogin(ctx, types.AuthConfig{
		ServerAddress: uri,
	})
	if err != nil {
		return err
	}

	return nil
}

func hasMacvlan0() bool {
	networks, err := docker.NetworkList(context.Background(), types.NetworkListOptions{})
	if err != nil {
		panic(err)
	}

	for _, network := range networks {
		if network.Name == "macvlan0" {
			return true
		}
	}

	return false
}

func cleanupClusters() error {
	log.Printf("Cleaning up dead clusters")

	clusters, err := getAllClusters(systemCtx)
	if err != nil {
		return err
	}

	var clustersToKill []string
	for _, cluster := range clusters {
		if cluster.Timeout.Before(time.Now()) {
			clustersToKill = append(clustersToKill, cluster.ID)
		}
	}

	signal := make(chan error)

	for _, clusterID := range clustersToKill {
		go func(clusterID string) {
			signal <- killCluster(systemCtx, clusterID)
		}(clusterID)
	}

	var killError error
	for range clustersToKill {
		err := <-signal
		if err != nil && killError == nil {
			killError = err
		}
	}
	if killError != nil {
		return killError
	}

	return nil
}

func getAndPrintClusters(ctx context.Context) {
	clusters, err := getAllClusters(ctx)
	if err != nil {
		log.Printf("Failed to fetch all clusters: %+v", err)
	} else {
		log.Printf("Clusters:")
		for _, cluster := range clusters {
			log.Printf("  %s [Owner: %s, Creator: %s, Timeout: %s]", cluster.ID, cluster.Owner, cluster.Creator, cluster.Timeout.Sub(time.Now()).Round(time.Second))
			for _, node := range cluster.Nodes {
				log.Printf("    %-16s  %-20s %-10s %-20s", node.ContainerID, node.Name, node.InitialServerVersion, node.IPv4Address)
			}
		}
	}
}

func Start() {
	// Open the meta-data database used to tracker ownership and expiry of clusters
	err := openMeta()
	if err != nil {
		log.Printf("Failed to open meta db: %s", err)
		return
	}

	// Connect to docker
	err = connectDocker()
	if err != nil {
		log.Printf("Failed to connect to docker: %s", err)
		return
	}

	// Check to make sure that the macvlan0 network is available in docker,
	// this is neccessary for the server instances we create to be available
	// on the public network.
	if !hasMacvlan0() {
		log.Printf("Failed to locate `macvlan0` network on docker host")
		return
	}

	// Create a system context to use for system actions (like cleanups)
	systemCtx = NewContext(context.Background(), "system", true)

	shutdownSig := make(chan struct{})
	cleanupClosedSig := make(chan struct{})

	// Start our cleanup routine which automatically cleans up clusters every 5 minutes
	go func() {
		for {
			select {
			case <-shutdownSig:
				cleanupClosedSig <- struct{}{}
				return
			case <-time.After(5 * time.Minute):
			}

			err := cleanupClusters()
			if err != nil {
				log.Printf("Failed to cleanup old clusters: %s", err)
			}
		}
	}()

	getAndPrintClusters(systemCtx)

	/*
		userCtx := NewContext(context.Background(), "brett@couchbase.com", false)

		getAndPrintClusters(systemCtx)

		err = killAllClusters(systemCtx)
		if err != nil {
			log.Printf("Failed to kill all clusters: %s", err)
			return
		}

		clusterOpts := ClusterOptions{
			Nodes: []NodeOptions{
				NodeOptions{
					Name:          "",
					ServerVersion: "5.5.0",
				},
				NodeOptions{
					Name:          "",
					ServerVersion: "5.5.0",
				},
				NodeOptions{
					Name:          "",
					ServerVersion: "5.5.0",
				},
			},
		}

		clusterID, err := allocateCluster(userCtx, clusterOpts)
		if err != nil {
			log.Printf("Failed to create new cluster: %s", err)
		} else {
			log.Printf("New Cluster: %s", clusterID)
		}

		getAndPrintClusters(userCtx)
	*/

	// Set up our REST server
	restServer := http.Server{
		Addr:    ":19923",
		Handler: createRESTRouter(),
	}

	// Set up a signal watcher for graceful shutdown
	c := make(chan os.Signal, 1)
	signal.Notify(c, os.Interrupt)
	go func() {
		<-c
		log.Printf("")
		log.Printf("Received shutdown signal.  Shutting down daemon.")

		restServer.Close()
	}()

	// Start listening now
	log.Printf("Daemon is starting on %s", restServer.Addr)
	restServer.ListenAndServe()

	// Signal all our running goroutines to shut down
	shutdownSig <- struct{}{}

	// Wait for the periodic cleanup routine to finish
	<-cleanupClosedSig

	// Close the meta-data database
	err = metaStore.Close()
	if err != nil {
		log.Printf("Failed to close meta db: %s", err)
	}

	// Let everyone know everything worked good
	log.Printf("Graceful shutdown completed.")
}
