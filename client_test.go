package allinkl

import (
	"context"
	"fmt"
	"log"
	"os"
	"sync"
	"testing"

	"github.com/joho/godotenv"
	"github.com/libdns/libdns"
)

func TestGetAllRecords(t *testing.T) {
	_ = godotenv.Load()
	username := os.Getenv("KAS_USERNAME")
	password := os.Getenv("KAS_PASSWORD")
	zone := os.Getenv("ZONE")

	if username == "" || password == "" {
		t.Skip("KAS_USERNAME and KAS_PASSWORD environment variables must be set")
	}

	p := &Provider{
		KasUsername: username,
		KasPassword: password,
	}

	ctx := context.Background()

	// Call the GetAllRecords method
	records, err := p.GetAllRecords(ctx, zone)

	if err != nil {
		t.Logf("GetAllRecords returned error (expected for now): %v", err)
		// Since the method is not fully implemented, we expect an error
		// Remove this condition once the method is properly implemented
		if records != nil {
			t.Errorf("Expected records to be nil when error occurs, got: %v", records)
		}
		return
	}

	t.Logf("Type: %T", records)

	log.Println("Records fetched:")
	for _, record := range records {
		rr := record.RR()
		t.Logf("%s (.%s): %s, %s\n", rr.Name, zone, rr.Data, rr.Type)
	}
}

func TestAppendRecord(t *testing.T) {
	_ = godotenv.Load()
	username := os.Getenv("KAS_USERNAME")
	password := os.Getenv("KAS_PASSWORD")
	zone := os.Getenv("ZONE")

	if username == "" || password == "" {
		t.Skip("KAS_USERNAME and KAS_PASSWORD environment variables must be set")
	}

	p := &Provider{
		KasUsername: username,
		KasPassword: password,
	}

	ctx := context.Background()

	record := libdns.RR{
		Type: "A",
		Name: "test",
		Data: "123.123.123.123",
		TTL:  3600, // 1 hour
	}

	// Call the AppendRecords method
	newRecord, err := p.AppendRecord(ctx, zone, record)

	if err != nil {
		t.Logf("AppendRecords returned error (expected for now): %v", err)
		// Since the method is not fully implemented, we expect an error
		// if newRecord != nil {
		// 	t.Errorf("Expected records to be nil when error occurs, got: %v", newRecord)
		// }
		return
	}

	t.Logf("Type: %T", newRecord)

	records, err := p.GetAllRecords(ctx, zone)

	if err != nil {
		t.Logf("GetAllRecords returned error (expected for now): %v", err)
		// Since the method is not fully implemented, we expect an error
		// Remove this condition once the method is properly implemented
		if records != nil {
			t.Errorf("Expected records to be nil when error occurs, got: %v", records)
		}
		return
	}

	log.Println("Records fetched:")
	for _, record := range records {
		rr := record.RR()
		t.Logf("%s (.%s): %s, %s\n", rr.Name, zone, rr.Data, rr.Type)
	}

}

func TestSetRecord(t *testing.T) {
	_ = godotenv.Load()
	username := os.Getenv("KAS_USERNAME")
	password := os.Getenv("KAS_PASSWORD")
	zone := os.Getenv("ZONE")

	if username == "" || password == "" {
		t.Skip("KAS_USERNAME and KAS_PASSWORD environment variables must be set")
	}

	p := &Provider{
		KasUsername: username,
		KasPassword: password,
	}

	ctx := context.Background()
	record := libdns.RR{
		Type: "A",
		Name: "test",
		Data: "124.124.124.124",
		TTL:  3600, // 1 hour
	}
	// Call the SetRecords method
	setRecord, err := p.SetRecord(ctx, zone, record)
	if err != nil {
		t.Logf("SetRecords returned error (expected for now): %v", err)
		// Since the method is not fully implemented, we expect an error
		// if records != nil {
		// 	t.Errorf("Expected records to be nil when error occurs, got: %v", records)
		// }
		return
	}

	t.Logf("Type: %T", setRecord)

	records, err := p.GetAllRecords(ctx, zone)

	if err != nil {
		t.Logf("GetAllRecords returned error (expected for now): %v", err)
		// Since the method is not fully implemented, we expect an error
		// Remove this condition once the method is properly implemented
		if records != nil {
			t.Errorf("Expected records to be nil when error occurs, got: %v", records)
		}
		return
	}

	log.Println("Records fetched:")
	for _, record := range records {
		rr := record.RR()
		t.Logf("%s (.%s): %s, %s\n", rr.Name, zone, rr.Data, rr.Type)
	}

}

func TestDeleteRecord(t *testing.T) {
	_ = godotenv.Load()
	username := os.Getenv("KAS_USERNAME")
	password := os.Getenv("KAS_PASSWORD")
	zone := os.Getenv("ZONE")

	if username == "" || password == "" {
		t.Skip("KAS_USERNAME and KAS_PASSWORD environment variables must be set")
	}

	p := &Provider{
		KasUsername: username,
		KasPassword: password,
	}

	ctx := context.Background()

	record := libdns.RR{
		Type: "A",
		Name: "test",
		Data: "124.124.124.124",
		TTL:  3600, // 1 hour
	}

	// Call the AppendRecords method
	deletedRecord, err := p.DeleteRecord(ctx, zone, record)

	if err != nil {
		t.Logf("AppendRecords returned error (expected for now): %v", err)
		// Since the method is not fully implemented, we expect an error
		// if records != nil {
		// 	t.Errorf("Expected records to be nil when error occurs, got: %v", records)
		// }
		return
	}

	t.Logf("Type: %T", deletedRecord)

	records, err := p.GetAllRecords(ctx, zone)

	if err != nil {
		t.Logf("GetAllRecords returned error (expected for now): %v", err)
		// Since the method is not fully implemented, we expect an error
		// Remove this condition once the method is properly implemented
		if records != nil {
			t.Errorf("Expected records to be nil when error occurs, got: %v", records)
		}
		return
	}

	log.Println("Records fetched:")
	for _, record := range records {
		rr := record.RR()
		t.Logf("%s (.%s): %s, %s\n", rr.Name, zone, rr.Data, rr.Type)
	}

}

// TestDeleteRecord_UniqueMatchWithDuplicateNames reproduces the scenario
// from libdns/all-inkl#2: two records sharing the same name but different
// values (as happens when solving DNS-01 challenges for a certificate and
// its wildcard counterpart at the same time — both create
// "_acme-challenge.<zone>" TXT records with different tokens). Under the
// old name-only matching, DeleteRecord could remove either one; it must now
// remove only the record whose name, type, AND value all match.
func TestDeleteRecord_UniqueMatchWithDuplicateNames(t *testing.T) {
	_ = godotenv.Load()
	username := os.Getenv("KAS_USERNAME")
	password := os.Getenv("KAS_PASSWORD")
	zone := os.Getenv("ZONE")

	if username == "" || password == "" {
		t.Skip("KAS_USERNAME and KAS_PASSWORD environment variables must be set")
	}

	p := &Provider{
		KasUsername: username,
		KasPassword: password,
	}

	ctx := context.Background()

	recordKeep := libdns.RR{Type: "TXT", Name: "_acme-challenge-test", Data: "token-keep-me", TTL: 600}
	recordDrop := libdns.RR{Type: "TXT", Name: "_acme-challenge-test", Data: "token-delete-me", TTL: 600}

	if _, err := p.AppendRecord(ctx, zone, recordKeep); err != nil {
		t.Fatalf("failed to create recordKeep: %v", err)
	}
	t.Cleanup(func() {
		_, _ = p.DeleteRecord(ctx, zone, recordKeep)
	})

	if _, err := p.AppendRecord(ctx, zone, recordDrop); err != nil {
		t.Fatalf("failed to create recordDrop: %v", err)
	}

	// Only recordDrop should be removed.
	if _, err := p.DeleteRecord(ctx, zone, recordDrop); err != nil {
		t.Fatalf("DeleteRecord(recordDrop) failed: %v", err)
	}

	records, err := p.GetAllRecords(ctx, zone)
	if err != nil {
		t.Fatalf("GetAllRecords failed: %v", err)
	}

	var foundKeep, foundDrop bool
	for _, record := range records {
		rr := record.RR()
		if rr.Type != "TXT" || rr.Name != "_acme-challenge-test" {
			continue
		}
		switch rr.Data {
		case recordKeep.Data:
			foundKeep = true
		case recordDrop.Data:
			foundDrop = true
		}
	}

	if !foundKeep {
		t.Errorf("recordKeep is missing — DeleteRecord matched the wrong record when two records shared a name")
	}
	if foundDrop {
		t.Errorf("recordDrop is still present — DeleteRecord failed to remove the targeted record")
	}
}

// TestConcurrentAppendRecords exercises kasCallMu by firing several
// AppendRecord calls at once, similar to Caddy solving multiple DNS-01
// challenges in parallel (see caddy-dns/all-inkl#2). Before serializing
// calls with a mutex, concurrent requests could race past the flood-delay
// check and get rejected by KAS's flood protection. If this test becomes
// flaky with rate-limit-shaped errors, that's a regression in the
// serialization, not the test.
func TestConcurrentAppendRecords(t *testing.T) {
	_ = godotenv.Load()
	username := os.Getenv("KAS_USERNAME")
	password := os.Getenv("KAS_PASSWORD")
	zone := os.Getenv("ZONE")

	if username == "" || password == "" {
		t.Skip("KAS_USERNAME and KAS_PASSWORD environment variables must be set")
	}

	p := &Provider{
		KasUsername: username,
		KasPassword: password,
	}

	ctx := context.Background()

	const n = 5
	records := make([]libdns.RR, n)
	for i := range records {
		records[i] = libdns.RR{
			Type: "TXT",
			Name: fmt.Sprintf("_acme-challenge-concurrent-%d", i),
			Data: fmt.Sprintf("token-%d", i),
			TTL:  600,
		}
	}

	t.Cleanup(func() {
		for _, r := range records {
			_, _ = p.DeleteRecord(ctx, zone, r)
		}
	})

	var wg sync.WaitGroup
	errs := make([]error, n)
	for i, r := range records {
		wg.Add(1)
		go func(i int, r libdns.RR) {
			defer wg.Done()
			_, err := p.AppendRecord(ctx, zone, r)
			errs[i] = err
		}(i, r)
	}
	wg.Wait()

	for i, err := range errs {
		if err != nil {
			t.Errorf("concurrent AppendRecord %d failed: %v (check that kasCallMu is serializing calls to the KAS API)", i, err)
		}
	}
}

// TestFindFaultString is a pure unit test (no credentials or network
// required) covering the bug behind caddy-dns/all-inkl#2: SOAP faults
// returned with a namespace prefix (e.g. "soap:Fault") were previously
// missed entirely because the old check only matched a bare "Fault" key,
// producing an unhelpful generic "invalid response format" error instead of
// the real KAS error message.
func TestFindFaultString(t *testing.T) {
	tests := []struct {
		name       string
		input      interface{}
		wantFound  bool
		wantString string
	}{
		{
			name: "bare Fault element",
			input: map[string]interface{}{
				"Fault": map[string]interface{}{
					"faultcode":   "soap:Client",
					"faultstring": "invalid credentials",
				},
			},
			wantFound:  true,
			wantString: "invalid credentials",
		},
		{
			name: "namespaced fault nested under Envelope/Body",
			input: map[string]interface{}{
				"soap:Envelope": map[string]interface{}{
					"soap:Body": map[string]interface{}{
						"soap:Fault": map[string]interface{}{
							"faultstring": map[string]interface{}{"#text": "too many requests"},
						},
					},
				},
			},
			wantFound:  true,
			wantString: "too many requests",
		},
		{
			name: "successful response has no fault",
			input: map[string]interface{}{
				"KasApiResponse": map[string]interface{}{
					"return": map[string]interface{}{
						"item": []interface{}{},
					},
				},
			},
			wantFound: false,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got, found := findFaultString(tt.input)
			if found != tt.wantFound {
				t.Fatalf("findFaultString() found = %v, want %v", found, tt.wantFound)
			}
			if found && got != tt.wantString {
				t.Errorf("findFaultString() = %q, want %q", got, tt.wantString)
			}
		})
	}
}

// TestExtractText is a pure unit test covering the small helper used by
// findFaultString to pull text out of either a plain string or an mxj
// "{#text: ...}" wrapper map.
func TestExtractText(t *testing.T) {
	if s, ok := extractText("plain string"); !ok || s != "plain string" {
		t.Errorf(`extractText("plain string") = (%q, %v), want ("plain string", true)`, s, ok)
	}
	if s, ok := extractText(map[string]interface{}{"#text": "wrapped string"}); !ok || s != "wrapped string" {
		t.Errorf(`extractText(wrapped) = (%q, %v), want ("wrapped string", true)`, s, ok)
	}
	if _, ok := extractText(42); ok {
		t.Errorf("extractText(42) expected ok=false for an unsupported type")
	}
}
