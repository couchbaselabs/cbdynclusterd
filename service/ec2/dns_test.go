package ec2

import (
	"context"
	"errors"
	"fmt"
	"strconv"
	"testing"

	"github.com/aws/aws-sdk-go-v2/aws"
	"github.com/aws/aws-sdk-go-v2/service/route53"
	route53types "github.com/aws/aws-sdk-go-v2/service/route53/types"
)

const testClusterID = "437c19a2"

// fakeRoute53 serves a zone split into pages and records the record sets it is asked to delete.
type fakeRoute53 struct {
	pages [][]route53types.ResourceRecordSet

	// failBatches makes any change batch with more than one change fail.
	failBatches bool
	// notFound and failing hold record names whose individual deletes fail.
	notFound map[string]bool
	failing  map[string]bool

	changeCalls int
	deleted     []route53types.ResourceRecordSet
}

func (f *fakeRoute53) ListResourceRecordSets(ctx context.Context, params *route53.ListResourceRecordSetsInput, optFns ...func(*route53.Options)) (*route53.ListResourceRecordSetsOutput, error) {
	page := 0
	if params.StartRecordName != nil {
		page, _ = strconv.Atoi(*params.StartRecordName)
	}

	out := &route53.ListResourceRecordSetsOutput{}
	if page < len(f.pages) {
		out.ResourceRecordSets = f.pages[page]
	}
	if page+1 < len(f.pages) {
		out.IsTruncated = true
		out.NextRecordName = aws.String(strconv.Itoa(page + 1))
		out.NextRecordType = route53types.RRTypeA
	}

	return out, nil
}

func (f *fakeRoute53) ChangeResourceRecordSets(ctx context.Context, params *route53.ChangeResourceRecordSetsInput, optFns ...func(*route53.Options)) (*route53.ChangeResourceRecordSetsOutput, error) {
	f.changeCalls++
	changes := params.ChangeBatch.Changes

	if f.failBatches && len(changes) > 1 {
		return nil, errors.New("batch rejected")
	}

	for _, change := range changes {
		name := aws.ToString(change.ResourceRecordSet.Name)
		if f.notFound[name] {
			return nil, &route53types.InvalidChangeBatch{
				Messages: []string{fmt.Sprintf("Tried to delete resource record set [name='%s', type='%s'] but it was not found", name, change.ResourceRecordSet.Type)},
			}
		}
		if f.failing[name] {
			return nil, errors.New("internal error")
		}
	}

	for _, change := range changes {
		if change.Action != route53types.ChangeActionDelete {
			return nil, fmt.Errorf("unexpected action %s", change.Action)
		}
		f.deleted = append(f.deleted, *change.ResourceRecordSet)
	}

	return &route53.ChangeResourceRecordSetsOutput{}, nil
}

func aRecord(name, ip string) route53types.ResourceRecordSet {
	return route53types.ResourceRecordSet{
		Name:            aws.String(name),
		Type:            route53types.RRTypeA,
		TTL:             aws.Int64(60),
		ResourceRecords: []route53types.ResourceRecord{{Value: aws.String(ip)}},
	}
}

func srvRecord(name string) route53types.ResourceRecordSet {
	return route53types.ResourceRecordSet{
		Name:            aws.String(name),
		Type:            route53types.RRTypeSrv,
		TTL:             aws.Int64(60),
		ResourceRecords: []route53types.ResourceRecord{{Value: aws.String("0 0 11210 node1-" + testClusterID + ".cbqeoc.com")}},
	}
}

func newTestService(fake *fakeRoute53) *EC2Service {
	return &EC2Service{
		route53Enabled: true,
		route53Client:  fake,
		hostedZoneId:   "Z2LV0HOGZIXZ6V",
		domainName:     "cbqeoc.com",
	}
}

func recordNames(sets []route53types.ResourceRecordSet) map[string]bool {
	names := make(map[string]bool)
	for _, set := range sets {
		names[aws.ToString(set.Name)] = true
	}
	return names
}

// clusterZone is a zone with the cluster's records (one with an upper-case name, one with a custom node
// name) split over two pages, mixed in with records that must not be touched.
func clusterZone() [][]route53types.ResourceRecordSet {
	return [][]route53types.ResourceRecordSet{
		{
			aRecord("mongo.cbqeoc.com.", "35.160.224.119"),
			aRecord("node1-"+testClusterID+".cbqeoc.com.", "3.139.100.174"),
			aRecord("node1-5918d74b.cbqeoc.com.", "3.137.220.157"),
			aRecord("node1-x"+testClusterID+".cbqeoc.com.", "1.1.1.1"),
			aRecord("foo.node1-"+testClusterID+".cbqeoc.com.", "1.1.1.2"),
			{Name: aws.String("node2-" + testClusterID + ".cbqeoc.com."), Type: route53types.RRTypeTxt},
		},
		{
			aRecord("NODE2-"+testClusterID+".cbqeoc.com.", "18.188.1.119"),
			aRecord("kv1-"+testClusterID+".cbqeoc.com.", "13.58.23.160"),
			srvRecord("_couchbase._tcp." + testClusterID + ".cbqeoc.com."),
			srvRecord("_couchbases._tcp." + testClusterID + ".cbqeoc.com."),
			srvRecord("_couchbase._tcp.5918d74b.cbqeoc.com."),
		},
	}
}

var clusterRecordNames = map[string]bool{
	"node1-" + testClusterID + ".cbqeoc.com.":            true,
	"NODE2-" + testClusterID + ".cbqeoc.com.":            true,
	"kv1-" + testClusterID + ".cbqeoc.com.":              true,
	"_couchbase._tcp." + testClusterID + ".cbqeoc.com.":  true,
	"_couchbases._tcp." + testClusterID + ".cbqeoc.com.": true,
}

func assertNames(t *testing.T, got map[string]bool, want map[string]bool) {
	t.Helper()
	if len(got) != len(want) {
		t.Fatalf("got records %v, want %v", got, want)
	}
	for name := range want {
		if !got[name] {
			t.Fatalf("missing record %s, got %v", name, got)
		}
	}
}

func TestClusterRecordSetsMatchesByName(t *testing.T) {
	s := newTestService(&fakeRoute53{pages: clusterZone()})

	sets, err := s.clusterRecordSets(context.Background(), testClusterID)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}

	assertNames(t, recordNames(sets), clusterRecordNames)
}

func TestRemoveClusterRecordsDeletesRoute53Values(t *testing.T) {
	fake := &fakeRoute53{pages: clusterZone()}
	s := newTestService(fake)

	n, err := s.removeClusterRecords(context.Background(), testClusterID)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if n != len(clusterRecordNames) {
		t.Fatalf("expected %d record sets, got %d", len(clusterRecordNames), n)
	}
	if fake.changeCalls != 1 {
		t.Fatalf("expected a single change batch, got %d", fake.changeCalls)
	}

	assertNames(t, recordNames(fake.deleted), clusterRecordNames)

	// the delete must carry the value Route 53 holds, not one derived from an instance
	for _, set := range fake.deleted {
		if aws.ToString(set.Name) == "kv1-"+testClusterID+".cbqeoc.com." {
			if got := aws.ToString(set.ResourceRecords[0].Value); got != "13.58.23.160" {
				t.Fatalf("expected delete of 13.58.23.160, got %s", got)
			}
		}
	}
}

func TestRemoveClusterRecordsFallsBackToIndividualDeletes(t *testing.T) {
	fake := &fakeRoute53{
		pages:       clusterZone(),
		failBatches: true,
		notFound:    map[string]bool{"node1-" + testClusterID + ".cbqeoc.com.": true},
	}
	s := newTestService(fake)

	_, err := s.removeClusterRecords(context.Background(), testClusterID)
	if err != nil {
		t.Fatalf("a record that is already gone should not be an error: %v", err)
	}

	want := make(map[string]bool)
	for name := range clusterRecordNames {
		want[name] = true
	}
	delete(want, "node1-"+testClusterID+".cbqeoc.com.")

	assertNames(t, recordNames(fake.deleted), want)
}

func TestRemoveClusterRecordsReportsFailuresButDeletesTheRest(t *testing.T) {
	failingName := "kv1-" + testClusterID + ".cbqeoc.com."
	fake := &fakeRoute53{
		pages:       clusterZone(),
		failBatches: true,
		failing:     map[string]bool{failingName: true},
	}
	s := newTestService(fake)

	_, err := s.removeClusterRecords(context.Background(), testClusterID)
	if err == nil {
		t.Fatal("expected an error for the record that could not be deleted")
	}

	want := make(map[string]bool)
	for name := range clusterRecordNames {
		want[name] = true
	}
	delete(want, failingName)

	assertNames(t, recordNames(fake.deleted), want)
}

func TestRemoveClusterRecordsWithNoRecords(t *testing.T) {
	fake := &fakeRoute53{pages: [][]route53types.ResourceRecordSet{{aRecord("mongo.cbqeoc.com.", "35.160.224.119")}}}
	s := newTestService(fake)

	n, err := s.removeClusterRecords(context.Background(), testClusterID)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if n != 0 || fake.changeCalls != 0 {
		t.Fatalf("expected no changes, got %d record sets and %d change calls", n, fake.changeCalls)
	}
}
