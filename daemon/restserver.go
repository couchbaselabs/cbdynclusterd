package daemon

import (
	"context"
	"errors"
	"log"
	"net/http"
	"net/url"
	"sort"
	"strconv"
	"strings"
	"time"

	"github.com/couchbaselabs/cbdynclusterd/dyncontext"
	"github.com/couchbaselabs/cbdynclusterd/helper"
	"github.com/couchbaselabs/cbdynclusterd/service"
	"github.com/couchbaselabs/cbdynclusterd/service/cloud"
	"github.com/couchbaselabs/cbdynclusterd/service/common"
	"github.com/couchbaselabs/cbdynclusterd/store"

	"github.com/gorilla/mux"
)

var Version string

func getHttpContext(r *http.Request) (context.Context, error) {
	userHeader := r.Header.Get("cbdn-user")
	if userHeader == "" {
		return nil, errors.New("must specify a user")
	}
	if !strings.HasSuffix(userHeader, "@couchbase.com") {
		return nil, errors.New("your user must be your @couchbase.com email")
	}
	user := userHeader

	ignoreOwnership := false
	adminHeader := r.Header.Get("cbdn-admin")
	if adminHeader == "true" {
		ignoreOwnership = true
	}

	return dyncontext.NewContext(r.Context(), user, ignoreOwnership), nil
}

func (d *daemon) HttpRoot(w http.ResponseWriter, r *http.Request) {
	w.Write([]byte("This is the cbdyncluster daemon!\n"))
}

type GetClustersJSON []ClusterJSON

func (d *daemon) HttpGetClusters(w http.ResponseWriter, r *http.Request) {
	reqCtx, err := getHttpContext(r)
	if err != nil {
		writeJSONError(w, err)
		return
	}

	clusters, err := d.getAllClusters(reqCtx)
	if err != nil {
		writeJSONError(w, err)
		return
	}

	jsonClusters := make(GetClustersJSON, 0)

	for _, c := range clusters {
		jsonCluster := jsonifyCluster(c)
		jsonClusters = append(jsonClusters, jsonCluster)
	}

	writeJsonResponse(w, jsonClusters)
}

func (d *daemon) HttpCreateCluster(w http.ResponseWriter, r *http.Request) {
	reqCtx, err := getHttpContext(r)
	if err != nil {
		writeJSONError(w, err)
		return
	}

	var reqData CreateClusterJSON
	err = readJsonRequest(r, &reqData)
	if err != nil {
		writeJSONError(w, err)
		return
	}

	timeout := 1 * time.Hour

	if reqData.Timeout != "" {
		clusterTimeout, err := time.ParseDuration(reqData.Timeout)
		if err != nil {
			writeJSONError(w, err)
			return
		}

		timeout = clusterTimeout
	}

	if timeout < 0 {
		writeJSONError(w, errors.New("must specify a valid timeout for the cluster"))
		return
	}
	if timeout > 2*7*24*time.Hour {
		writeJSONError(w, errors.New("cannot allocate clusters for longer than 2 weeks"))
		return
	}
	clusterOpts := service.AllocateClusterOptions{
		Deadline: time.Now().Add(timeout),
	}

	var platform = store.ClusterPlatformDocker

	for _, node := range reqData.Nodes {
		nodeOpts := service.CreateNodeOptions{
			Name:                node.Name,
			Platform:            node.Platform,
			ServerVersion:       node.ServerVersion,
			UseCommunityEdition: node.UseCommunityEdition,
			OS:                  node.OS,
			Arch:                node.Arch,
		}
		clusterOpts.Nodes = append(clusterOpts.Nodes, nodeOpts)
		if node.Platform == "ec2" {
			platform = store.ClusterPlatformEC2
		} else if node.Platform == "docker" {
			platform = store.ClusterPlatformDocker
		} else if node.Platform == "cloud" {
			platform = store.ClusterPlatformCloud
		}
	}

	var s service.UnmanagedClusterService
	if platform == store.ClusterPlatformCloud {
		writeJSONError(w, errors.New("cannot allocate a cluster using the cloud service"))
		return
	}

	clusterID := helper.NewRandomClusterID()
	clusterOpts.ClusterID = clusterID

	meta := store.ClusterMeta{
		Owner:    dyncontext.ContextUser(reqCtx),
		Timeout:  clusterOpts.Deadline,
		Platform: store.ClusterPlatform(platform),
		OS:       reqData.Nodes[0].OS,
	}
	if err := d.metaStore.CreateClusterMeta(clusterID, meta); err != nil {
		writeJSONError(w, err)
		return
	}

	if platform == store.ClusterPlatformDocker {
		s = d.dockerService
	} else if platform == store.ClusterPlatformEC2 {
		s = d.ec2Service
	}

	for {
		err = s.AllocateCluster(reqCtx, clusterOpts)
		if err == service.MaxCapacityError {
			// update timeout and try again
			clusterOpts.Deadline = time.Now().Add(timeout)

			err = d.metaStore.UpdateClusterMeta(clusterID, func(meta store.ClusterMeta) (store.ClusterMeta, error) {
				meta.Timeout = clusterOpts.Deadline
				return meta, nil
			})

			if err == nil {
				time.Sleep(time.Duration(1) * time.Minute)
				continue
			}

			// fall through if error updating timeout
		}
		// allocate or meta update failed
		if err != nil {
			writeJSONError(w, err)
			return
		}
		// successfully allocated cluster
		break
	}

	newClusterJson := NewClusterJSON{
		ID: clusterID,
	}
	writeJsonResponse(w, newClusterJson)
}

type GetClusterJSON ClusterJSON

func (d *daemon) HttpGetCluster(w http.ResponseWriter, r *http.Request) {
	reqCtx, err := getHttpContext(r)
	if err != nil {
		writeJSONError(w, err)
		return
	}

	clusterID := mux.Vars(r)["cluster_id"]

	meta, err := d.metaStore.GetClusterMeta(clusterID)
	if err != nil {
		log.Printf("Encountered unregistered cluster: %s", clusterID)
		writeJSONError(w, err)
		return
	}

	var s service.ClusterService
	if meta.Platform == store.ClusterPlatformCloud {
		s = d.cloudService
	} else if meta.Platform == store.ClusterPlatformDocker {
		s = d.dockerService
	} else if meta.Platform == store.ClusterPlatformEC2 {
		s = d.ec2Service
	} else {
		log.Printf("Cluster found with no platform, assuming docker: %s", clusterID)
		s = d.dockerService
	}

	c, err := s.GetCluster(reqCtx, clusterID)
	if err != nil {
		writeJSONError(w, err)
		return
	}

	jsonCluster := jsonifyCluster(c)

	writeJsonResponse(w, jsonCluster)
}

func (d *daemon) HttpGetDockerHost(w http.ResponseWriter, r *http.Request) {
	hostURI, err := url.Parse(dockerHost)
	if err != nil {
		writeJSONError(w, err)
		return
	}

	if hostURI.Scheme != "tcp" {
		writeJSONError(w, errors.New("docker is not configured via tcp and cannot return the docker host"))
		return
	}

	jsonResp := &DockerHostJSON{
		Hostname: hostURI.Hostname(),
		Port:     hostURI.Port(),
	}
	writeJsonResponse(w, jsonResp)
	return
}

func HttpGetVersion(w http.ResponseWriter, r *http.Request) {
	jsonResp := &VersionJSON{
		Version: Version,
	}
	writeJsonResponse(w, jsonResp)
	return
}

func (d *daemon) HttpSetupCluster(w http.ResponseWriter, r *http.Request) {
	reqCtx, err := getHttpContext(r)
	if err != nil {
		writeJSONError(w, err)
		return
	}

	clusterID := mux.Vars(r)["cluster_id"]

	var reqData CreateClusterSetupJSON
	err = readJsonRequest(r, &reqData)
	if err != nil {
		writeJSONError(w, err)
		return
	}

	meta, err := d.metaStore.GetClusterMeta(clusterID)
	if err != nil {
		log.Printf("Encountered unregistered cluster: %s", clusterID)
		writeJSONError(w, err)
		return
	}

	var s service.ClusterService
	if meta.Platform == store.ClusterPlatformCloud {
		writeJSONError(w, errors.New("cannot setup a cloud cluster"))
		return
	} else if meta.Platform == store.ClusterPlatformDocker {
		s = d.dockerService
	} else if meta.Platform == store.ClusterPlatformEC2 {
		s = d.ec2Service
	} else {
		log.Printf("Cluster found with no platform, assuming docker: %s", clusterID)
		s = d.dockerService
	}

	c, err := s.GetCluster(reqCtx, clusterID)
	if err != nil {
		writeJSONError(w, err)
		return
	}
	if len(c.Nodes) != len(reqData.Services) {
		writeJSONError(w, errors.New("services does not map to number of nodes"))
		return
	}

	epnode, err := common.SetupCluster(common.ClusterSetupOptions{
		Nodes:               c.Nodes,
		Services:            reqData.Services,
		UseHostname:         reqData.UseHostname || meta.Platform == store.ClusterPlatformEC2,
		UseIpv6:             reqData.UseIpv6,
		MemoryQuota:         strconv.Itoa(reqData.RamQuota),
		User:                reqData.User,
		StorageMode:         reqData.StorageMode,
		Bucket:              reqData.Bucket,
		UseDeveloperPreview: reqData.UseDeveloperPreview,
	})
	if err != nil {
		writeJSONError(w, err)
		return
	}

	c.EntryPoint = epnode

	jsonCluster := jsonifyCluster(c)
	writeJsonResponse(w, jsonCluster)
	return
}

func (d *daemon) HttpSetupClusterEncryption(w http.ResponseWriter, r *http.Request) {
	reqCtx, err := getHttpContext(r)
	if err != nil {
		writeJSONError(w, err)
		return
	}

	clusterID := mux.Vars(r)["cluster_id"]

	var reqData SetupClusterEncryptionJSON
	err = readJsonRequest(r, &reqData)
	if err != nil {
		writeJSONError(w, err)
		return
	}

	meta, err := d.metaStore.GetClusterMeta(clusterID)
	if err != nil {
		log.Printf("Encountered unregistered cluster: %s", clusterID)
		writeJSONError(w, err)
		return
	}

	var s service.ClusterService
	if meta.Platform == store.ClusterPlatformCloud {
		writeJSONError(w, errors.New("cannot setup a cloud cluster"))
		return
	} else if meta.Platform == store.ClusterPlatformDocker {
		s = d.dockerService
	} else if meta.Platform == store.ClusterPlatformEC2 {
		s = d.ec2Service
	} else {
		log.Printf("Cluster found with no platform, assuming docker: %s", clusterID)
		s = d.dockerService
	}

	useSecure := reqData.Level == "strict"

	// update meta so we know to connect over secure ports or not for commands
	err = d.metaStore.UpdateClusterMeta(clusterID, func(meta store.ClusterMeta) (store.ClusterMeta, error) {
		meta.UseSecure = useSecure
		return meta, nil
	})
	if err != nil {
		writeJSONError(w, errors.New("couldn't update cluster meta"))
		return
	}

	err = common.SetupClusterEncryption(reqCtx, s, clusterID, service.SetupClusterEncryptionOptions{
		Level:     reqData.Level,
		UseSecure: useSecure,
	})
	if err != nil {
		writeJSONError(w, err)
		return
	}

	w.WriteHeader(200)
}

func (d *daemon) HttpUpdateCluster(w http.ResponseWriter, r *http.Request) {
	reqCtx, err := getHttpContext(r)
	if err != nil {
		writeJSONError(w, err)
		return
	}

	clusterID := mux.Vars(r)["cluster_id"]

	var reqData UpdateClusterJSON
	err = readJsonRequest(r, &reqData)
	if err != nil {
		writeJSONError(w, err)
		return
	}

	if reqData.Timeout != "" {
		newTimeout, err := time.ParseDuration(reqData.Timeout)
		if err != nil {
			writeJSONError(w, err)
			return
		}

		if err := d.refreshCluster(reqCtx, clusterID, newTimeout); err != nil {
			writeJSONError(w, err)
			return
		}

		w.WriteHeader(200)
		return
	}

	writeJSONError(w, errors.New("not sure what you wanted to do"))
}

func (d *daemon) HttpDeleteCluster(w http.ResponseWriter, r *http.Request) {
	reqCtx, err := getHttpContext(r)
	if err != nil {
		writeJSONError(w, err)
		return
	}

	clusterID := mux.Vars(r)["cluster_id"]

	meta, err := d.metaStore.GetClusterMeta(clusterID)
	if err != nil {
		log.Printf("Encountered unregistered cluster: %s", clusterID)
		writeJSONError(w, err)
		return
	}

	var s service.ClusterService
	if meta.Platform == store.ClusterPlatformCloud {
		s = d.cloudService
	} else if meta.Platform == store.ClusterPlatformDocker {
		s = d.dockerService
	} else if meta.Platform == store.ClusterPlatformEC2 {
		s = d.ec2Service
	} else {
		log.Printf("Cluster found with no platform, assuming docker: %s", clusterID)
		s = d.dockerService
	}

	err = s.KillCluster(reqCtx, clusterID)
	if err != nil {
		writeJSONError(w, err)
		return
	}

	w.WriteHeader(200)
}

func (d *daemon) HttpAddBucket(w http.ResponseWriter, r *http.Request) {
	reqCtx, err := getHttpContext(r)
	if err != nil {
		writeJSONError(w, err)
		return
	}

	clusterID := mux.Vars(r)["cluster_id"]

	var reqData AddBucketJSON
	err = readJsonRequest(r, &reqData)
	if err != nil {
		writeJSONError(w, err)
		return
	}

	meta, err := d.metaStore.GetClusterMeta(clusterID)
	if err != nil {
		log.Printf("Encountered unregistered cluster: %s", clusterID)
		writeJSONError(w, err)
		return
	}

	var s service.ClusterService
	if meta.Platform == store.ClusterPlatformCloud {
		s = d.cloudService
	} else if meta.Platform == store.ClusterPlatformDocker {
		s = d.dockerService
	} else if meta.Platform == store.ClusterPlatformEC2 {
		s = d.ec2Service
	} else {
		log.Printf("Cluster found with no platform, assuming docker: %s", clusterID)
		s = d.dockerService
	}

	err = s.AddBucket(reqCtx, clusterID, service.AddBucketOptions{
		Name:           reqData.Name,
		StorageMode:    reqData.StorageMode,
		RamQuota:       reqData.RamQuota,
		UseHostname:    reqData.UseHostname,
		ReplicaCount:   reqData.ReplicaCount,
		BucketType:     reqData.BucketType,
		EvictionPolicy: reqData.EvictionPolicy,
		StorageBackend: reqData.StorageBackend,
		UseSecure:      meta.UseSecure,
	})
	if err != nil {
		writeJSONError(w, err)
		return
	}

	w.WriteHeader(200)
}

func (d *daemon) HttpAddSampleBucket(w http.ResponseWriter, r *http.Request) {
	reqCtx, err := getHttpContext(r)
	if err != nil {
		writeJSONError(w, err)
		return
	}

	clusterID := mux.Vars(r)["cluster_id"]

	var reqData AddSampleBucketJSON
	err = readJsonRequest(r, &reqData)
	if err != nil {
		writeJSONError(w, err)
		return
	}

	meta, err := d.metaStore.GetClusterMeta(clusterID)
	if err != nil {
		log.Printf("Encountered unregistered cluster: %s", clusterID)
		writeJSONError(w, err)
		return
	}

	var s service.ClusterService
	if meta.Platform == store.ClusterPlatformCloud {
		s = d.cloudService
	} else if meta.Platform == store.ClusterPlatformDocker {
		s = d.dockerService
	} else if meta.Platform == store.ClusterPlatformEC2 {
		s = d.ec2Service
	} else {
		log.Printf("Cluster found with no platform, assuming docker: %s", clusterID)
		s = d.dockerService
	}

	err = s.AddSampleBucket(reqCtx, clusterID, service.AddSampleOptions{
		SampleBucket: reqData.SampleBucket,
		UseHostname:  reqData.UseHostname,
		UseSecure:    meta.UseSecure,
	})
	if err != nil {
		writeJSONError(w, err)
		return
	}

	w.WriteHeader(200)
}

func (d *daemon) HttpAddCollection(w http.ResponseWriter, r *http.Request) {
	reqCtx, err := getHttpContext(r)
	if err != nil {
		writeJSONError(w, err)
		return
	}

	clusterID := mux.Vars(r)["cluster_id"]

	var reqData AddCollectionJSON
	err = readJsonRequest(r, &reqData)
	if err != nil {
		writeJSONError(w, err)
		return
	}

	meta, err := d.metaStore.GetClusterMeta(clusterID)
	if err != nil {
		log.Printf("Encountered unregistered cluster: %s", clusterID)
		writeJSONError(w, err)
		return
	}

	var s service.ClusterService
	if meta.Platform == store.ClusterPlatformCloud {
		s = d.cloudService
	} else if meta.Platform == store.ClusterPlatformDocker {
		s = d.dockerService
	} else if meta.Platform == store.ClusterPlatformEC2 {
		s = d.ec2Service
	} else {
		log.Printf("Cluster found with no platform, assuming docker: %s", clusterID)
		s = d.dockerService
	}

	err = s.AddCollection(reqCtx, clusterID, service.AddCollectionOptions{
		Name:        reqData.Name,
		ScopeName:   reqData.ScopeName,
		BucketName:  reqData.BucketName,
		UseHostname: reqData.UseHostname,
		UseSecure:   meta.UseSecure,
	})
	if err != nil {
		writeJSONError(w, err)
		return
	}

	w.WriteHeader(200)
}

func (d *daemon) HttpAddIP(w http.ResponseWriter, r *http.Request) {
	reqCtx, err := getHttpContext(r)
	if err != nil {
		writeJSONError(w, err)
		return
	}

	clusterID := mux.Vars(r)["cluster_id"]

	var reqData AddIPJSON
	err = readJsonRequest(r, &reqData)
	if err != nil {
		writeJSONError(w, err)
		return
	}

	meta, err := d.metaStore.GetClusterMeta(clusterID)
	if err != nil {
		log.Printf("Encountered unregistered cluster: %s", clusterID)
		writeJSONError(w, err)
		return
	}

	var s service.ClusterService
	if meta.Platform == store.ClusterPlatformCloud {
		s = d.cloudService
	} else if meta.Platform == store.ClusterPlatformDocker {
		s = d.dockerService
	} else if meta.Platform == store.ClusterPlatformEC2 {
		s = d.ec2Service
	} else {
		log.Printf("Cluster found with no platform, assuming docker: %s", clusterID)
		s = d.dockerService
	}

	err = s.AddIP(reqCtx, clusterID, reqData.IP)
	if err != nil {
		writeJSONError(w, err)
		return
	}

	w.WriteHeader(200)
}

func (d *daemon) HttpAddUser(w http.ResponseWriter, r *http.Request) {
	reqCtx, err := getHttpContext(r)
	if err != nil {
		writeJSONError(w, err)
		return
	}

	clusterID := mux.Vars(r)["cluster_id"]

	var reqData AddUserJSON
	err = readJsonRequest(r, &reqData)
	if err != nil {
		writeJSONError(w, err)
		return
	}

	meta, err := d.metaStore.GetClusterMeta(clusterID)
	if err != nil {
		log.Printf("Encountered unregistered cluster: %s", clusterID)
		writeJSONError(w, err)
		return
	}

	var s service.ClusterService
	if meta.Platform == store.ClusterPlatformCloud {
		s = d.cloudService
	} else if meta.Platform == store.ClusterPlatformDocker {
		s = d.dockerService
	} else if meta.Platform == store.ClusterPlatformEC2 {
		s = d.ec2Service
	} else {
		log.Printf("Cluster found with no platform, assuming docker: %s", clusterID)
		s = d.dockerService
	}

	err = s.AddUser(reqCtx, clusterID, reqData.User, reqData.Bucket)
	if err != nil {
		writeJSONError(w, err)
		return
	}

	w.WriteHeader(200)
}

func (d *daemon) HttpConnString(w http.ResponseWriter, r *http.Request) {
	reqCtx, err := getHttpContext(r)
	if err != nil {
		writeJSONError(w, err)
		return
	}

	clusterID := mux.Vars(r)["cluster_id"]

	var reqData ConnStringJSON
	err = readJsonRequest(r, &reqData)
	if err != nil {
		writeJSONError(w, err)
		return
	}

	meta, err := d.metaStore.GetClusterMeta(clusterID)
	if err != nil {
		log.Printf("Encountered unregistered cluster: %s", clusterID)
		writeJSONError(w, err)
		return
	}

	var s service.ClusterService
	if meta.Platform == store.ClusterPlatformCloud {
		s = d.cloudService
	} else if meta.Platform == store.ClusterPlatformDocker {
		s = d.dockerService
	} else if meta.Platform == store.ClusterPlatformEC2 {
		s = d.ec2Service
	} else {
		log.Printf("Cluster found with no platform, assuming docker: %s", clusterID)
		s = d.dockerService
	}

	connstr, err := s.ConnString(reqCtx, clusterID, reqData.UseSSL, reqData.UseSrv)
	if err != nil {
		writeJSONError(w, err)
		return
	}

	connStrJson := ConnStringResponseJSON{
		ConnStr: connstr,
	}
	writeJsonResponse(w, connStrJson)
}

func (d *daemon) HttpSetupClientCertAuth(w http.ResponseWriter, r *http.Request) {
	reqCtx, err := getHttpContext(r)
	if err != nil {
		writeJSONError(w, err)
		return
	}

	clusterID := mux.Vars(r)["cluster_id"]

	var reqData SetupClientCertAuthJSON
	err = readJsonRequest(r, &reqData)
	if err != nil {
		writeJSONError(w, err)
		return
	}

	meta, err := d.metaStore.GetClusterMeta(clusterID)
	if err != nil {
		log.Printf("Encountered unregistered cluster: %s", clusterID)
		writeJSONError(w, err)
		return
	}

	var s service.ClusterService
	if meta.Platform == store.ClusterPlatformCloud {
		s = d.cloudService
	} else if meta.Platform == store.ClusterPlatformDocker {
		s = d.dockerService
	} else if meta.Platform == store.ClusterPlatformEC2 {
		s = d.ec2Service
	} else {
		log.Printf("Cluster found with no platform, assuming docker: %s", clusterID)
		s = d.dockerService
	}

	var numRoots int
	if reqData.NumRoots > 0 {
		numRoots = reqData.NumRoots
	} else {
		numRoots = 1
	}

	certData, err := s.SetupCertAuth(reqCtx, clusterID, service.SetupClientCertAuthOptions{
		UserName:  reqData.UserName,
		UserEmail: reqData.UserEmail,
		NumRoots:  numRoots,
	})
	if err != nil {
		writeJSONError(w, err)
		return
	}

	writeJsonResponse(w, CertAuthResultJSON{
		CACert:     certData.CACert,
		ClientKey:  certData.ClientKey,
		ClientCert: certData.ClientCert,
	})
	return
}

func (d *daemon) HttpBuildImage(w http.ResponseWriter, r *http.Request) {
	reqCtx, err := getHttpContext(r)
	if err != nil {
		writeJSONError(w, err)
		return
	}

	var reqData BuildImageJSON
	err = readJsonRequest(r, &reqData)
	if err != nil {
		writeJSONError(w, err)
		return
	}

	image, err := d.dockerService.EnsureImageExists(reqCtx, reqData.ServerVersion, reqData.OS, reqData.Arch, reqData.UseCommunityEdition)
	if err != nil {
		writeJSONError(w, err)
		return
	}

	imageJSON := BuildImageResponseJSON{
		ImageName: image,
	}
	writeJsonResponse(w, imageJSON)
}

func (d *daemon) HttpCreateCloudCluster(w http.ResponseWriter, r *http.Request) {
	reqCtx, err := getHttpContext(r)
	if err != nil {
		writeJSONError(w, err)
		return
	}

	var reqData CreateCloudClusterJSON
	err = readJsonRequest(r, &reqData)
	if err != nil {
		writeJSONError(w, err)
		return
	}

	timeout := 1 * time.Hour

	if reqData.Timeout != "" {
		clusterTimeout, err := time.ParseDuration(reqData.Timeout)
		if err != nil {
			writeJSONError(w, err)
			return
		}

		timeout = clusterTimeout
	}

	if timeout < 0 {
		writeJSONError(w, errors.New("must specify a valid timeout for the cluster"))
		return
	}
	if timeout > 2*7*24*time.Hour {
		writeJSONError(w, errors.New("cannot allocate clusters for longer than 2 weeks"))
		return
	}

	services := make(map[string]uint32)
	for _, s := range reqData.Services {
		sp := strings.Split(s, ",")
		sort.Strings(sp)
		key := strings.Join(sp, ",")
		if _, ok := services[key]; !ok {
			services[key] = 0
		}

		services[key]++
	}

	var nodes []cloud.NodeSetupOptions
	for k, s := range services {
		servicesStr := strings.Split(k, ",")
		services := []cloud.V3CouchbaseService{}
		for _, serviceStr := range servicesStr {
			service, err := cloud.ParseServiceName(serviceStr)
			if err != nil {
				writeJSONError(w, err)
				return
			}
			services = append(services, service)
		}
		nodes = append(nodes, cloud.NodeSetupOptions{
			Services: services,
			Size:     s,
		})
	}

	clusterID := helper.NewRandomClusterID()
	clusterOpts := cloud.ClusterSetupOptions{
		Nodes: nodes,
	}

	cloudClusterID, err := d.cloudService.SetupCluster(reqCtx, clusterID, clusterOpts, helper.RestTimeout)
	if err != nil {
		writeJSONError(w, err)
		return
	}

	dCtx, cancel := context.WithDeadline(reqCtx, time.Now().Add(helper.RestTimeout))
	defer cancel()

	meta := store.ClusterMeta{
		Owner:          dyncontext.ContextUser(reqCtx),
		Timeout:        time.Now().Add(timeout),
		Platform:       store.ClusterPlatformCloud,
		CloudClusterID: cloudClusterID,
	}
	if err := d.metaStore.CreateClusterMeta(clusterID, meta); err != nil {
		writeJSONError(w, err)
		return
	}

	c, err := d.cloudService.GetCluster(dCtx, clusterID)
	if err != nil {
		writeJSONError(w, err)
		return
	}

	newClusterJson := jsonifyCluster(c)
	writeJsonResponse(w, newClusterJson)
}

func (d *daemon) HttpRegisterCloudCluster(w http.ResponseWriter, r *http.Request) {
	reqCtx, err := getHttpContext(r)
	if err != nil {
		writeJSONError(w, err)
		return
	}

	var reqData RegisterCloudClusterJSON
	err = readJsonRequest(r, &reqData)
	if err != nil {
		writeJSONError(w, err)
		return
	}

	log.Printf("Registering cloud cluster for %s: %s", reqData.ClusterID, reqData.CloudClusterID)

	meta := store.ClusterMeta{
		Owner:          dyncontext.ContextUser(reqCtx),
		Timeout:        time.Now().Add(1 * time.Hour),
		Platform:       store.ClusterPlatformCloud,
		CloudClusterID: reqData.CloudClusterID,
	}
	if err := d.metaStore.CreateClusterMeta(reqData.ClusterID, meta); err != nil {
		writeJSONError(w, err)
		return
	}

	w.WriteHeader(200)
}

func (d *daemon) createRESTRouter() *mux.Router {
	r := mux.NewRouter()
	r.HandleFunc("/", d.HttpRoot)
	r.HandleFunc("/docker-host", d.HttpGetDockerHost).Methods("GET")
	r.HandleFunc("/version", HttpGetVersion).Methods("GET")
	r.HandleFunc("/clusters", d.HttpGetClusters).Methods("GET")
	r.HandleFunc("/clusters", d.HttpCreateCluster).Methods("POST")
	r.HandleFunc("/create-cloud", d.HttpCreateCloudCluster).Methods("POST")
	r.HandleFunc("/cluster/{cluster_id}", d.HttpGetCluster).Methods("GET")
	r.HandleFunc("/cluster/{cluster_id}", d.HttpUpdateCluster).Methods("PUT")
	r.HandleFunc("/cluster/{cluster_id}/setup", d.HttpSetupCluster).Methods("POST")
	r.HandleFunc("/cluster/{cluster_id}/setup-cluster-encryption", d.HttpSetupClusterEncryption).Methods("POST")
	r.HandleFunc("/cluster/{cluster_id}", d.HttpDeleteCluster).Methods("DELETE")
	r.HandleFunc("/cluster/{cluster_id}/add-bucket", d.HttpAddBucket).Methods("POST")
	r.HandleFunc("/cluster/{cluster_id}/add-sample-bucket", d.HttpAddSampleBucket).Methods("POST")
	r.HandleFunc("/cluster/{cluster_id}/add-collection", d.HttpAddCollection).Methods("POST")
	r.HandleFunc("/cluster/{cluster_id}/setup-cert-auth", d.HttpSetupClientCertAuth).Methods("POST")
	r.HandleFunc("/cluster/{cluster_id}/add-ip", d.HttpAddIP).Methods("POST")
	r.HandleFunc("/cluster/{cluster_id}/add-user", d.HttpAddUser).Methods("POST")
	r.HandleFunc("/cluster/{cluster_id}/connstr", d.HttpConnString).Methods("GET")
	r.HandleFunc("/images", d.HttpBuildImage).Methods("POST")
	r.HandleFunc("/register-cloud-cluster", d.HttpRegisterCloudCluster).Methods("POST")
	return r
}
