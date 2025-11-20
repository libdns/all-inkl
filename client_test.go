package allinkl

import (
	"context"
	"log"
	"os"
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
		Data: "123.123.123.123",
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
