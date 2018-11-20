package helper

import (
	"fmt"
	"os"
	"flag"
	"regexp"
	"errors"
	"time"
	"net/http"
	"encoding/base64"
	"github.com/golang/glog"
	"io/ioutil"
	"strconv"
	"github.com/couchbase/gocb"
	"github.com/couchbase/gocb/cbft"
	"strings"
)

var (
	IniFile        *string
	Slowlog        bool
	RestRetry = 60
	RestTimeout = 60*time.Second
	WaitTimeout = 30*time.Second
	restInterval = 3*time.Second
	PattActual, _ = regexp.Compile("\\s*vb_active_itm_memory:\\s*([0-9]+)")
	PattActualReplica, _ = regexp.Compile("\\s*vb_replica_itm_memory:\\s*([0-9]+)")
	PattUncompressed, _ = regexp.Compile("\\s*vb_active_itm_memory_uncompressed:\\s*([0-9]+)")
	PattUncompressedReplica, _ = regexp.Compile("\\s*vb_replica_itm_memory_uncompressed:\\s*([0-9]+)")
	StopWorkload = false
	WorkloadRunTime = 10*time.Second
	WorkloadRampTime = 10*time.Second
)

const (
	SshPort              = 22
	RestPort             = 8091
	N1qlPort             = 8093
	FtsPort              = 8094
	SshUser              = "root"
	SshPass              = "couchbase"
	RestUser             = "Administrator"
	RestPass             = "password"
	BucketCouchbase      = "membase"
	BucketMemcached      = "memcached"
	BucketEphemeral      = "ephemeral"
	PPools               = "/pools"
	PRebalanceStop       = "/controller/stopRebalance"
	PPoolsNodes        = "/pools/nodes"
	PBuckets           = "/pools/default/buckets"
	PFailover          = "/controller/failOver"
	PEject             = "/controller/ejectNode"
	PSetupServices     = "/node/controller/setupServices"
	PPoolsDefault      = "/pools/default"
	PSettingsWeb       = "/settings/web"
	PRbacUsers         = "/settings/rbac/users/local"
	PAddNode           = "/controller/addNode"
	PNodesSelf         = "/nodes/self"
	PRebalance         = "/controller/rebalance"
	PRebalanceProgress = "/pools/default/rebalanceProgress"
	PSettingsIndexes   = "/settings/indexes"
	PN1ql              = "/query"
	PFts               = "/api/index"

	Domain             = "/domain"

	DockerFilePath = "deps/sdkqe-resource/dockerfiles/"

)

type UserOption struct {
	Name string
	Password string
	Roles *[]string
}

type BucketOption struct {
	Name string
	Type string
	Password string
}

type stop struct {
	error
}

type SubFields struct {
	SubValue string
	RecurringField string
}

type KvData struct {
	PropValue string
	SubFields SubFields
}

type MemUsedStats struct {
	Uncompressed int
	Used int
}

func (m *MemUsedStats) Diff () int {
	return m.Uncompressed - m.Used
}

type Cred struct {
	Username string
	Password string
	Hostname string
	Port     int
	Roles    *[]string
}

type RestCall struct {
	ExpectedCode int
	RetryOnCode int
	Method string
	Path string
	Cred *Cred
	Body string
	Header map[string]string
	ContentType string
}

func Usage() {
	fmt.Fprintf(os.Stderr, "Test all: go test ./... -stderrthreshold=[INFO|WARN|FATAL] -log_dir=[string]\n"+
		"Test a file(traceability_test.go): go test ./traceability/traceability_test.go  -stderrthreshold=[INFO|WARN|FATAL] -log_dir=[string]\n"+
		"Test single(TestTraceability): go test -run TestTraceability  -stderrthreshold=[INFO|WARN|FATAL] -log_dir=[string]\n")
	flag.PrintDefaults()
	os.Exit(2)
}

func LoadData(bucketName, ep, username, password string, numItems int) (*gocb.Bucket, error) {
	goCluster, err := gocb.Connect("couchbase://"+ep)
	glog.Infof("connect to %s, %s with %s %s", ep, bucketName, username, password)
	if err != nil { return nil, err }
	goCluster.Authenticate(gocb.PasswordAuthenticator{
		Username: username,
		Password: password,
	})
	bucket, err := goCluster.OpenBucket(bucketName, "")
	if err != nil { return nil, err }

	for i := 0; i < numItems; i++ {
		if err := Upsert(bucket, i); err != nil {
			return nil, err
		}
	}
	return bucket, nil
}

func Get(bucket *gocb.Bucket, i int) error {
	kvData := KvData{}
	_, err := bucket.Get(strconv.Itoa(i), &kvData)

	if kvData.PropValue != "SampleValue"+strconv.Itoa(i) ||
		kvData.SubFields.SubValue != "SampleSubvalue"+strconv.Itoa(i) ||
		kvData.SubFields.RecurringField != "RecurringSubvalue" {
		return errors.New("Not expected data from Get operation")
	}
	return err
}

func Upsert(bucket *gocb.Bucket, i int) error {
	_, err := bucket.Upsert(strconv.Itoa(i),
		KvData {
			PropValue: "SampleValue"+strconv.Itoa(i),
			SubFields: SubFields {
				SubValue: "SampleSubvalue"+strconv.Itoa(i),
				RecurringField: "RecurringSubvalue",
			},
		}, 0)
	return err
}

func Remove(bucket *gocb.Bucket, i int) error {
	key := strconv.Itoa(i)
	if _, err := bucket.Remove(key, 0); err != nil { return err }

	var val string
	if _, err := bucket.Get(key, &val); err != nil {
		if err == gocb.ErrKeyNotFound {
			return nil
		}
		return err
	} else {
		return errors.New("key "+key+" is expected to be removed but exists!")
	}
}

func RemoveKeyIfExists(bucket *gocb.Bucket, key string) error {
	var val interface{}
	_, err := bucket.Get(key, &val)
	if err != nil {
		if err == gocb.ErrKeyNotFound {
			return nil
		} else {
			return err
		}
	} else {
		_, err := bucket.Remove(key,0)
		return err
	}
}

func N1qlWorkload(bucket *gocb.Bucket, numItems int, chErr chan error) {
	valIndex := 0
	for !StopWorkload {
		valIndex = (valIndex + 1) % numItems
		statement := fmt.Sprintf("SELECT * from %s where PropValue = 'SampleValue%d'", bucket.Name(), valIndex)
		query := gocb.NewN1qlQuery(statement)
		rows, err := bucket.ExecuteN1qlQuery(query, nil)
		if err != nil {
			chErr <- err
			return
		}
		if rows == nil {
			chErr <- errors.New("Unexpected result from N1ql. rows is null")
			return
		}
	}
	chErr <- nil
}

func FtsWorkload(bucket *gocb.Bucket, ftsIndexName string, numItems int, chErr chan error) {
	valIndex := 0
	for !StopWorkload {
		valIndex = (valIndex+1) % numItems
		str := fmt.Sprintf("SampleValue%d", valIndex)
		query := gocb.NewSearchQuery(ftsIndexName, cbft.NewMatchQuery(fmt.Sprintf(str)))
		res, err := bucket.ExecuteSearchQuery(query)
		if err != nil {
			chErr <- err
			return
		}

		arrErr := res.Errors()

		if len(arrErr) > 0 || len(res.Hits()) != 1 {
			var msg string

			if len(arrErr) > 0 {
				msg += strings.Join(arrErr, ",")
			}

			if len(res.Hits()) != 1 {
				msg += fmt.Sprintf("%s:Hits expected 1 but was %d",str, res.Hits())
			}
			chErr <- errors.New("Error from FTS:"+msg)
			return
		}
	}
	chErr <- nil
}

func KvGetWorkload(bucket *gocb.Bucket, numItems int, chErr chan error) {
	valIndex := 0
	for !StopWorkload {
		valIndex = (valIndex+1) % numItems
		if err := Get(bucket, valIndex); err != nil {
			chErr <- err
			return
		}
	}
	chErr <- nil
}

func KvUpsertWorkload(bucket *gocb.Bucket, numItems int, chErr chan error) {
	valIndex := 0
	for !StopWorkload {
		valIndex = (valIndex+1) % numItems
		if err := Upsert(bucket, valIndex); err != nil {
			chErr <- err
			return
		}
	}
	chErr <- nil
}

func RestRetryer(retry int, params *RestCall, fn func(*RestCall) (string, error) ) (string, error) {

	var body string
	var err error
	if body, err = fn(params); err != nil {
		if s, ok := err.(stop); ok {
			return "", s.error
		}

		if retry--; retry > 0 {
			glog.Infof("Retrying %v %d more times in 1 sec", fn, retry)
			time.Sleep(restInterval)
			return RestRetryer(retry, params, fn)
		}
		return "", err
	}
	return body, nil
}

func Tuple(version string) (int, int, int){
	v, err := MatchingStrings("\\s*([0-9]+).([0-9]+).([0-9,^-]+)\\s*", version)

	if err != nil {
		return 0,0,0
	}
	v1, _ := strconv.Atoi(v[1])
	v2, _ := strconv.Atoi(v[2])
	v3, _ := strconv.Atoi(v[3])
	return v1, v2, v3
}

func GetResponse(params *RestCall) (string, error) {
	expected := params.ExpectedCode
	retryOnCode := params.RetryOnCode
	method := params.Method
	path := params.Path
	login := params.Cred
	postBody := params.Body
	header := params.Header

	client := &http.Client{Timeout: RestTimeout}
	url := fmt.Sprintf("http://%s:%d%s", login.Hostname, login.Port, path)
	// ** debug

	if path == PSetupServices {
		a := "a"
		b := a
		a = b
	/*	buf := new(bytes.Buffer)
		buf.ReadFrom(postBody)
		a = buf.String()
		b = a*/
	}

	req, err := http.NewRequest(method, url, strings.NewReader(postBody))
	if err != nil { return "", err }
	req.Header.Set("Authorization", "Basic "+base64.StdEncoding.EncodeToString([]byte(login.Username+":"+login.Password)))
	contentType := "application/x-www-form-urlencoded"
	if params.ContentType != "" {
		contentType = params.ContentType
	}
	req.Header.Set("Content-Type", contentType)
	for k,v := range header {
		req.Header.Set(k, v)
	}

	glog.Infof("request:%s", req.URL.Path)
	res, err := client.Do(req)
	if err != nil {
		glog.Infof("Server might not be ready yet.:%s", err)
		return "", err
	}
	defer res.Body.Close()

	s := res.StatusCode
	switch {
	case s == expected:
		glog.Infof("%s returned %d", url, s)
		respBody, err := ioutil.ReadAll(res.Body)
		if err != nil { return "", err }
		return string(respBody), nil
	case s == retryOnCode: // expected response when server is not ready for this request yet
		glog.Infof("%s returned %d which is expected when server is not ready yet", url, s)
		respBody, _ := ioutil.ReadAll(res.Body)
		return "", errors.New(string(respBody))
	default:
		respBody, err := ioutil.ReadAll(res.Body)
		glog.Infof("respBody=%s, err=%s", string(respBody), err)
		return "", stop {fmt.Errorf("Request:%v,PostBody:%s,Response:%d:%s", req, postBody, s, string(respBody))}
	}
}

func MatchingString(pattern string, str string) (string, error) {
	re, err := regexp.Compile(pattern)
	if err != nil {
		msg := fmt.Sprintf("Cannot compile regular expression %s", re)
		return "", errors.New(msg)
	}
	matched := re.FindStringSubmatch(str)
	if matched != nil {
		return matched[1], nil
	} else {
		return "", errors.New("No matches found")
	}
}

func MatchingStrings(pattern string, str string) ([]string, error) {
	re, err := regexp.Compile(pattern)
	if err != nil {
		msg := fmt.Sprintf("Cannot compile regular expression %s", re)
		return nil, errors.New(msg)
	}
	return re.FindStringSubmatch(str), nil

}

