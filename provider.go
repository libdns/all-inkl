// Package libdnstemplate implements a DNS record management client compatible
// with the libdns interfaces for all-ink.com.
package allinkl

import (
	"context"
	"fmt"

	"github.com/libdns/libdns"
)

// Provider facilitates DNS record manipulation with all-ink.com.
type Provider struct {
	KasUsername string `json:"kas_username,omitempty"`
	KasPassword string `json:"kas_password,omitempty"`
}

// GetRecords lists all the records in the zone.
func (p *Provider) GetRecords(ctx context.Context, zone string) ([]libdns.Record, error) {
	libdnsRecords, err := p.GetAllRecords(ctx, zone)
	return libdnsRecords, err
}

// AppendRecords adds records to the zone. It returns the records that were added.
func (p *Provider) AppendRecords(ctx context.Context, zone string, records []libdns.Record) ([]libdns.Record, error) {
	// Make sure to return RR-type-specific structs, not libdns.RR structs.

	var createdRecords []libdns.Record
	for _, record := range records {
		libdnsRecord, err := p.AppendRecord(ctx, zone, record)
		if err != nil {
			return nil, fmt.Errorf("failed to append record %v: %w", record, err)
		}
		createdRecords = append(createdRecords, libdnsRecord.RR())
	}
	return createdRecords, nil
}

// SetRecords sets the records in the zone, either by updating existing records or creating new ones.
// It returns the updated records.
func (p *Provider) SetRecords(ctx context.Context, zone string, records []libdns.Record) ([]libdns.Record, error) {
	// Make sure to return RR-type-specific structs, not libdns.RR structs.

	var updatedRecords []libdns.Record
	for _, record := range records {
		libdnsRecord, err := p.SetRecord(ctx, zone, record)
		if err != nil {
			return nil, fmt.Errorf("failed to set record %v: %w", record, err)
		}
		updatedRecords = append(updatedRecords, libdnsRecord.RR())
	}
	return updatedRecords, nil
}

// DeleteRecords deletes the specified records from the zone. It returns the records that were deleted.
func (p *Provider) DeleteRecords(ctx context.Context, zone string, records []libdns.Record) ([]libdns.Record, error) {
	var deletedRecords []libdns.Record
	for _, record := range records {
		libdnsRecord, err := p.DeleteRecord(ctx, zone, record)
		if err != nil {
			return nil, fmt.Errorf("failed to delete record %v: %w", record, err)
		}
		deletedRecords = append(deletedRecords, libdnsRecord.RR())
	}
	return deletedRecords, nil
}

// Interface guards
var (
	_ libdns.RecordGetter   = (*Provider)(nil)
	_ libdns.RecordAppender = (*Provider)(nil)
	_ libdns.RecordSetter   = (*Provider)(nil)
	_ libdns.RecordDeleter  = (*Provider)(nil)
)
