package daemon

import (
	"context"
	"errors"
	"log"
	"net/http"
	"os"
	"os/signal"
	"sync"
	"time"

	"github.com/BurntSushi/toml"
	"github.com/couchbaselabs/cbdynclusterd/cluster"
	"github.com/couchbaselabs/cbdynclusterd/dyncontext"
	"github.com/couchbaselabs/cbdynclusterd/helper"
	"github.com/couchbaselabs/cbdynclusterd/service"
	"github.com/couchbaselabs/cbdynclusterd/service/cloud"
	"github.com/couchbaselabs/cbdynclusterd/service/docker"
	"github.com/couchbaselabs/cbdynclusterd/service/ec2"
	"github.com/couchbaselabs/cbdynclusterd/store"

	goflag "flag"
	"fmt"
	"path"

	"github.com/docker/docker/api/types"
	"github.com/docker/docker/client"
	"github.com/mitchellh/go-homedir"
	"github.com/spf13/cobra"
	"github.com/spf13/pflag"
)

var (
	defaultCfgFileName = ".cbdynclusterd.toml"

	defaultDockerRegistry            = "dockerhub.build.couchbase.com"
	defaultDockerHost                = "/var/run/docker.sock"
	defaultAliasRepoPath             = helper.AliasRepoPath
	defaultDockerMaxContainers int32 = -1

	cfgFileFlag string

	config Config
)

type Config struct {
	AliasRepo         string                         `toml:"alias-repo"`
	Docker            docker.DockerConfig            `toml:"docker"`
	EC2               ec2.EC2Config                  `toml:"ec2"`
	Capella           map[string]cloud.CapellaConfig `toml:"capella"`
	DefaultCapellaEnv string                         `toml:"default-capella-env"`
}

var rootCmd = &cobra.Command{
	Use:   "cbdynclusterd",
	Short: "Launches cbdyncluster daemon",
	Long:  "Launches cbdyncluster daemon",
	Run: func(cmd *cobra.Command, args []string) {
		startDaemon()
	},
}

// Execute starts our daemon service.
func Execute() {
	cobra.OnInitialize(initConfig)
	pflag.CommandLine.AddGoFlagSet(goflag.CommandLine)
	goflag.CommandLine.Parse([]string{})
	rootCmd.PersistentFlags().StringVar(&cfgFileFlag, "config", "", "config file (default is $HOME/"+defaultCfgFileName+")")

	if err := rootCmd.Execute(); err != nil {
		fmt.Println(err)
		os.Exit(1)
	}
}

func initConfig() {
	configFile := cfgFileFlag
	if configFile == "" {
		// use default config file
		home, err := homedir.Dir()
		if err != nil {
			fmt.Println(err)
			os.Exit(1)
		}

		configFile = path.Join(home, defaultCfgFileName)
	}

	_, err := toml.DecodeFile(configFile, &config)
	if err != nil {
		fmt.Println(err)
		os.Exit(1)
	}

	if config.Docker.Host == "" {
		config.Docker.Host = defaultDockerHost
	}

	if config.Docker.Registry == "" {
		config.Docker.Registry = defaultDockerRegistry
	}

	if config.Docker.MaxContainers == 0 {
		config.Docker.MaxContainers = defaultDockerMaxContainers
	}

	if config.AliasRepo == "" {
		config.AliasRepo = defaultAliasRepoPath
	}
}

type daemon struct {
	metaStore *store.MetaDataStore
	systemCtx context.Context

	dockerService *docker.DockerService
	cloudService  *cloud.CloudService
	ec2Service    *ec2.EC2Service
}

func (d *daemon) openMeta() error {
	meta := &store.MetaDataStore{}

	err := meta.Open("./data")
	if err != nil {
		return err
	}

	d.metaStore = meta
	return nil
}

func (d *daemon) connectDocker() (*client.Client, error) {
	return client.NewClient(config.Docker.Host, "1.38", nil, nil)
}

func (d *daemon) hasMacvlan0(cli *client.Client) bool {
	networks, err := cli.NetworkList(context.Background(), types.NetworkListOptions{})
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

func (d *daemon) getAllClusters(ctx context.Context) ([]*cluster.Cluster, error) {
	clusters := []*cluster.Cluster{}

	dockerClusters, err := d.dockerService.GetAllClusters(ctx)
	if err != nil {
		log.Printf("Failed to get all clusters %v\n", err)
		return nil, err
	}

	clusters = append(clusters, dockerClusters...)

	cloudClusters, err := d.cloudService.GetAllClusters(ctx)
	if err != nil && !errors.Is(err, cloud.ErrCloudNotEnabled) {
		log.Printf("Failed to get all clusters %v\n", err)
		return nil, err
	}

	clusters = append(clusters, cloudClusters...)

	ec2Clusters, err := d.ec2Service.GetAllClusters(ctx)
	if err != nil && !errors.Is(err, ec2.ErrEC2NotEnabled) {
		log.Printf("Failed to get all clusters %v\n", err)
		return nil, err
	}

	clusters = append(clusters, ec2Clusters...)

	return clusters, nil
}

func (d *daemon) cleanupClusters() {
	log.Printf("Cleaning up dead clusters")

	clusters, err := d.getAllClusters(d.systemCtx)
	if err != nil {
		log.Printf("Failed to get all clusters %v\n", err)
	}

	var clustersToKill []string
	for _, c := range clusters {
		if c.Timeout.Before(time.Now()) {
			clustersToKill = append(clustersToKill, c.ID)
		}
	}

	var wg sync.WaitGroup
	for _, clusterID := range clustersToKill {
		meta, err := d.metaStore.GetClusterMeta(clusterID)
		if err != nil {
			log.Printf("Failed to kill cluster %s: %v\n", clusterID, err)
			continue
		}

		wg.Add(1)
		go func(clusterID string, platform store.ClusterPlatform) {
			var s service.ClusterService
			if platform == store.ClusterPlatformCloud {
				s = d.cloudService
			} else if platform == store.ClusterPlatformDocker {
				s = d.dockerService
			} else if platform == store.ClusterPlatformEC2 {
				s = d.ec2Service
			} else {
				log.Printf("Cluster found with no platform, assuming docker: %s", clusterID)
				s = d.dockerService
			}

			if err := s.KillCluster(d.systemCtx, clusterID); err != nil {
				log.Printf("Failed to kill cluster %s: %v\n", clusterID, err)
			}
			wg.Done()
		}(clusterID, meta.Platform)
	}

	wg.Wait()
	return
}

func (d *daemon) getAndPrintClusters() {
	clusters, err := d.getAllClusters(d.systemCtx)
	if err != nil {
		log.Printf("Failed to fetch all clusters: %+v", err)
		return
	}

	log.Printf("Clusters:")
	for _, c := range clusters {
		log.Printf("  %s [Owner: %s, Creator: %s, Timeout: %s]", c.ID, c.Owner, c.Creator, c.Timeout.Sub(time.Now()).Round(time.Second))
		for _, node := range c.Nodes {
			hostname := node.IPv4Address
			if node.Hostname != "" {
				hostname = node.Hostname
			}
			log.Printf("    %-16s  %-20s %-10s %-20s", node.ContainerID, node.Name, node.InitialServerVersion, hostname)
		}
	}
}

func newDaemon() *daemon {
	d := &daemon{}
	// Open the meta-data database used to tracker ownership and expiry of clusters
	err := d.openMeta()
	if err != nil {
		log.Fatalf("Failed to open meta db: %s", err)
	}

	// Connect to docker
	cli, err := d.connectDocker()
	if err != nil {
		log.Fatalf("Failed to connect to docker: %s", err)
	}

	// Check to make sure that the macvlan0 network is available in docker,
	// this is necessary for the server instances we create to be available
	// on the public network.
	if !d.hasMacvlan0(cli) {
		log.Printf("Failed to locate `macvlan0` network on docker host")
	}

	readOnlyStore := store.NewReadOnlyMetaDataStore(d.metaStore)
	d.dockerService = docker.NewDockerService(cli, config.AliasRepo, config.Docker, readOnlyStore)
	d.cloudService = cloud.NewCloudService(config.DefaultCapellaEnv, config.Capella, d.metaStore)
	d.ec2Service = ec2.NewEC2Service(config.EC2, config.AliasRepo, readOnlyStore)

	// Create a system context to use for system actions (like cleanups)
	d.systemCtx = dyncontext.NewContext(context.Background(), "system", true)

	return d
}

func (d *daemon) Run() {
	shutdownSig := make(chan struct{})
	cleanupClosedSig := make(chan struct{})

	// Start our cleanup routine which automatically cleans up clusters every 5 minutes
	go func() {
		for {
			select {
			case <-shutdownSig:
				close(cleanupClosedSig)
				return
			case <-time.After(5 * time.Minute):
			}

			d.cleanupClusters()
		}
	}()

	d.getAndPrintClusters()

	// Set up our REST server
	restServer := http.Server{
		Addr:    ":19923",
		Handler: d.createRESTRouter(),
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
	if err := restServer.ListenAndServe(); err != nil {
		log.Fatalf("Error:%s", err)
	}

	// Signal all our running goroutines to shut down
	close(shutdownSig)

	// Wait for the periodic cleanup routine to finish
	<-cleanupClosedSig

	// Close the meta-data database
	if err := d.metaStore.Close(); err != nil {
		log.Fatalf("Failed to close meta db: %s", err)
	}

	// Let everyone know everything worked good
	log.Printf("Graceful shutdown completed.")
}

func startDaemon() {
	d := newDaemon()
	d.Run()
}
