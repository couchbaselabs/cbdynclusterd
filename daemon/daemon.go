package daemon

import (
	"context"
	"github.com/couchbaselabs/cbdynclusterd/cluster"
	"github.com/couchbaselabs/cbdynclusterd/dyncontext"
	"github.com/couchbaselabs/cbdynclusterd/helper"
	"github.com/couchbaselabs/cbdynclusterd/service/docker"
	"github.com/couchbaselabs/cbdynclusterd/store"
	"log"
	"net/http"
	"os"
	"os/signal"
	"sync"
	"time"

	goflag "flag"
	"fmt"
	"io/ioutil"
	"path"

	"github.com/docker/docker/api/types"
	"github.com/docker/docker/client"
	"github.com/mitchellh/go-homedir"
	"github.com/pelletier/go-toml"
	"github.com/spf13/cobra"
	"github.com/spf13/pflag"
	"github.com/spf13/viper"
)

var defaultCfgFileName = ".cbdynclusterd.toml"

var dockerRegistry = "dockerhub.build.couchbase.com"
var dockerHost = "/var/run/docker.sock"
var dnsSvcHost = ""

var aliasRepoPath = helper.AliasRepoPath

var cfgFileFlag string
var dockerRegistryFlag, dockerHostFlag, dnsSvcHostFlag, aliasRepoPathFlag string
var dockerPortFlag int32

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
	if err := rootCmd.Execute(); err != nil {
		fmt.Println(err)
		os.Exit(1)
	}
}

func init() {
	cobra.OnInitialize(initConfig)

	pflag.CommandLine.AddGoFlagSet(goflag.CommandLine)
	goflag.CommandLine.Parse([]string{})
	rootCmd.PersistentFlags().StringVar(&cfgFileFlag, "config", "", "config file (default is $HOME/"+defaultCfgFileName+")")
	rootCmd.PersistentFlags().StringVar(&dockerRegistryFlag, "docker-registry", dockerRegistry, "docker registry to pull/push images")
	rootCmd.PersistentFlags().StringVar(&dockerHostFlag, "docker-host", dockerHost, "docker host where containers are running (i.e. tcp://127.0.0.1:2376)")
	rootCmd.PersistentFlags().StringVar(&dnsSvcHostFlag, "dns-host", dnsSvcHost, "Restful DNS server IP")
	rootCmd.PersistentFlags().StringVar(&aliasRepoPathFlag, "alias-repo", dnsSvcHost, "Path to the alias repo")

	rootCmd.PersistentFlags().Int32Var(&dockerPortFlag, "docker-port", 0, "")
	rootCmd.PersistentFlags().MarkDeprecated("docker-port", "Deprecated flag to specify the port of the docker host")
}

func initConfig() {
	if cfgFileFlag == "" {
		// use default config file
		home, err := homedir.Dir()
		if err != nil {
			fmt.Println(err)
			os.Exit(1)
		}

		configFile := path.Join(home, defaultCfgFileName)
		viper.SetConfigFile(configFile)

		// Read configuration file. If not exists, create and set with default values
		if _, err := os.Stat(configFile); os.IsNotExist(err) {
			if err = createConfigFile(configFile); err != nil {
				fmt.Printf("Error:%s\n", err)
				return
			}
		}
	} else {
		// if user specified the config file, use it
		viper.SetConfigFile(cfgFileFlag)
	}

	viper.AutomaticEnv()
	viper.ReadInConfig()

	getStringArg := func(arg string) string {
		if rootCmd.PersistentFlags().Changed(arg) {
			val, _ := rootCmd.PersistentFlags().GetString(arg)
			return val
		}
		return viper.GetString(arg)
	}

	getInt32Arg := func(arg string) int32 {
		if rootCmd.PersistentFlags().Changed(arg) {
			val, _ := rootCmd.PersistentFlags().GetInt32(arg)
			return val
		}
		return viper.GetInt32(arg)
	}

	dockerRegistryFlag = getStringArg("docker-registry")
	dockerHostFlag = getStringArg("docker-host")
	dockerPortFlag = getInt32Arg("docker-port")
	dnsSvcHostFlag = getStringArg("dns-host")
	aliasRepoPathFlag = getStringArg("alias-repo")

	dockerRegistry = dockerRegistryFlag
	dockerHost = dockerHostFlag
	dnsSvcHost = dnsSvcHostFlag
	aliasRepoPath = aliasRepoPathFlag

	if dockerPortFlag > 0 {
		dockerHost = fmt.Sprintf("tcp://%s:%d", dockerHostFlag, dockerPortFlag)
	}
}

func createConfigFile(configFile string) error {
	tmap, err := toml.TreeFromMap(nil)
	if err != nil {
		return err
	}

	tmap.Set("docker-registry", dockerRegistryFlag)
	tmap.Set("docker-host", dockerHostFlag)
	tmap.Set("dns-host", dnsSvcHostFlag)

	if dockerPortFlag > 0 {
		tmap.Set("docker-port", dockerPortFlag)
	}

	return ioutil.WriteFile(configFile, []byte(tmap.String()), 0644)
}

type daemon struct {
	metaStore *store.MetaDataStore
	systemCtx context.Context

	dockerService *docker.DockerService
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
	return client.NewClient(dockerHost, "1.38", nil, nil)
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
	clusters, err := d.dockerService.GetAllClusters(ctx)
	if err != nil {
		log.Printf("Failed to get all clusters %v\n", err)
		return nil, err
	}

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
		wg.Add(1)
		go func(clusterID string) {
			if err := d.dockerService.KillCluster(d.systemCtx, clusterID); err != nil {
				log.Printf("Failed to kill cluster %s: %v\n", clusterID, err)
			}
			wg.Done()
		}(clusterID)
	}

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
			log.Printf("    %-16s  %-20s %-10s %-20s", node.ContainerID, node.Name, node.InitialServerVersion, node.IPv4Address)
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
	d.dockerService = docker.NewDockerService(cli, dockerRegistry, dnsSvcHost, aliasRepoPath, readOnlyStore)

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
