package allinkl

import (
	"context"
	"encoding/json"
	"fmt"
	"log"
	"net/http"
	"strings"
	"sync"
	"time"

	"github.com/clbanning/mxj"
	"github.com/libdns/libdns"
	"github.com/tiaguinho/gosoap"
)

// ApiBase is the URL for the KAS API WSDL.
const ApiBase = "https://kasapi.kasserver.com/soap/wsdl/KasApi.wsdl"

// TimeoutTime is the default timeout for API requests.
const TimeoutTime = 15000 * time.Millisecond

// ChachedRecords stores cached DNS records for zones to minimize API calls.
var ChachedRecords = make(map[string][]allinklRecord)

// kasCallMu serializes all KAS SOAP calls across goroutines.
//
// The KAS API enforces a minimum delay between requests ("flood
// protection") and this package tracks that delay via
// waitForFloodDelay/updateFloodDelay. Without a mutex, concurrent callers
// (e.g. Caddy solving several DNS-01 challenges for a SAN certificate, or
// two ACME issuers racing at once) can each pass the delay check at nearly
// the same instant and then both call KAS simultaneously, tripping the
// flood limit. KAS's rejection in that case does not always come back as a
// plain <Fault> element (see findFaultString below), which previously
// surfaced as an unhelpful "invalid response format" error. Holding this
// lock around each full request/response round trip guarantees calls are
// fully serialized and the flood delay is honored.
var kasCallMu sync.Mutex

// findFaultString searches a decoded SOAP response for a fault message,
// regardless of XML namespace prefix.
//
// mxj preserves namespace prefixes as part of map keys, so a real SOAP
// fault can come back as "Fault", "soap:Fault", "SOAP-ENV:Fault", etc.
// The previous fault-detection only ever checked the bare "Fault" key, so
// namespaced faults (and other unexpected shapes) were missed entirely and
// fell through to a generic "invalid response format" error that hid the
// actual reason (auth failure, unknown zone, rate limiting, ...). This walks
// the whole decoded structure looking for any key containing "faultstring"
// and returns its text.
func findFaultString(v interface{}) (string, bool) {
	switch t := v.(type) {
	case map[string]interface{}:
		for k, val := range t {
			if strings.Contains(strings.ToLower(k), "faultstring") {
				if s, ok := extractText(val); ok && s != "" {
					return s, true
				}
			}
		}
		for _, val := range t {
			if s, ok := findFaultString(val); ok {
				return s, true
			}
		}
	case []interface{}:
		for _, item := range t {
			if s, ok := findFaultString(item); ok {
				return s, true
			}
		}
	}
	return "", false
}

// extractText pulls a plain string out of either a raw string value or an
// mxj "{#text: ...}" wrapper map.
func extractText(v interface{}) (string, bool) {
	switch t := v.(type) {
	case string:
		return t, true
	case map[string]interface{}:
		if s, ok := t["#text"].(string); ok {
			return s, true
		}
	}
	return "", false
}

// GetAllRecords retrieves all DNS records for the specified zone from the KAS API.
func (p *Provider) GetAllRecords(ctx context.Context, zone string) ([]libdns.Record, error) {

	httpClient := &http.Client{
		Timeout: TimeoutTime,
	}
	soap, err := gosoap.SoapClient(ApiBase, httpClient)
	if err != nil {
		fmt.Println("Error creating SOAP client:", err)
	}

	// Prepare parameters like PHP script
	params := map[string]interface{}{
		"zone_host": strings.TrimSuffix(zone, ".") + ".",
	}

	requestData := map[string]interface{}{
		"kas_login":        p.KasUsername,
		"kas_auth_type":    "plain",
		"kas_auth_data":    p.KasPassword,
		"kas_action":       "get_dns_settings",
		"KasRequestParams": params,
	}

	// JSON encode the entire request like PHP
	jsonData, err := json.Marshal(requestData)
	if err != nil {
		log.Fatalf("Error encoding JSON: %v", err)
	}

	kasCallMu.Lock()
	defer kasCallMu.Unlock()
	p.waitForFloodDelay()

	// Call the SOAP method with JSON-encoded params
	res, err := soap.Call("KasApi", gosoap.Params{
		"Params": string(jsonData),
	})
	if err != nil {
		log.Fatalf("Error calling SOAP method: %v", err)
	}
	if res == nil {
		log.Fatal("Response is nil")
	}
	mv, err := mxj.NewMapXml([]byte(res.Body))
	if err != nil {
		log.Fatalf("Error converting XML to map: %v", err)
	}

	records := []interface{}{}
	// Defensive navigation through the nested map
	root, ok := mv["KasApiResponse"].(map[string]interface{})
	if ok {
		ret, ok := root["return"].(map[string]interface{})
		if ok {
			items := ret["item"]
			var itemList []interface{}
			switch v := items.(type) {
			case []interface{}:
				itemList = v
			case map[string]interface{}:
				itemList = []interface{}{v}
			}
			for _, item := range itemList {
				mitem, _ := item.(map[string]interface{})
				keyMap, _ := mitem["key"].(map[string]interface{})
				key, _ := keyMap["#text"].(string)
				if key == "Response" {
					val, _ := mitem["value"].(map[string]interface{})
					respItems := val["item"]
					var respList []interface{}
					switch v := respItems.(type) {
					case []interface{}:
						respList = v
					case map[string]interface{}:
						respList = []interface{}{v}
					}
					for _, respItem := range respList {
						respMap, _ := respItem.(map[string]interface{})
						rkeyMap, _ := respMap["key"].(map[string]interface{})
						rkey, _ := rkeyMap["#text"].(string)
						if rkey == "ReturnInfo" {
							rval, _ := respMap["value"].(map[string]interface{})
							arr := rval["item"]
							switch v := arr.(type) {
							case []interface{}:
								records = v
							case map[string]interface{}:
								records = []interface{}{v}
							}
						}
					}
				}
			}
		}
	}

	// Initialize recordsList with enough elements
	recordsList := make([]libdns.Record, len(records))
	rawRecords := make([]allinklRecord, len(records))

	for i, rec := range records {
		recMap, _ := rec.(map[string]interface{})

		items := recMap["item"]
		var kvList []interface{}
		switch v := items.(type) {
		case []interface{}:
			kvList = v
		case map[string]interface{}:
			kvList = []interface{}{v}
		}

		// Create a temporary record for this entry
		currentRecord := allinklRecord{}

		for _, kv := range kvList {
			kvMap, _ := kv.(map[string]interface{})
			keyMap, _ := kvMap["key"].(map[string]interface{})
			key, _ := keyMap["#text"].(string)
			valueMap, valueIsMap := kvMap["value"].(map[string]interface{})
			var value interface{}
			if valueIsMap {
				value, _ = valueMap["#text"]
			} else {
				value = kvMap["value"]
			}

			// Set fields in the temporary Record struct
			switch key {
			case "record_id":
				if strVal, ok := value.(string); ok {
					currentRecord.ID = strVal
				}
			case "record_zone":
				if strVal, ok := value.(string); ok {
					currentRecord.ZoneID = strVal
				}
			case "record_type":
				if strVal, ok := value.(string); ok {
					currentRecord.Type = strVal
				}
			case "record_name":
				if strVal, ok := value.(string); ok {
					currentRecord.Name = strVal
				} else if value == nil {
					// For apex/root domain records, name might be nil
					currentRecord.Name = "@"
				}
			case "record_data":
				if strVal, ok := value.(string); ok {
					currentRecord.Value = strVal
				}
			case "record_ttl":
				if ttlVal, ok := value.(float64); ok {
					currentRecord.TTL = int(ttlVal)
				} else if ttlStr, ok := value.(string); ok {
					// Try to parse string to int if needed
					var ttl int
					fmt.Sscanf(ttlStr, "%d", &ttl)
					currentRecord.TTL = ttl
				}
			}
		}

		rawRecords[i] = currentRecord
		var libdnsRecord, err = currentRecord.toLibdnsRecord(zone)
		if err != nil {
			log.Printf("Error converting record to libdns format: %v", err)
			continue
		}
		recordsList[i] = libdnsRecord
	}

	ChachedRecords[zone] = rawRecords

	return recordsList, nil
}

// AppendRecord adds a single DNS record to the specified zone.
func (p *Provider) AppendRecord(ctx context.Context, zone string, record libdns.Record) ([]libdns.Record, error) {

	httpClient := &http.Client{
		Timeout: TimeoutTime,
	}
	soap, err := gosoap.SoapClient(ApiBase, httpClient)
	if err != nil {
		return nil, fmt.Errorf("error creating SOAP client: %w", err)
	}

	// Convert the record to RR to access its fields
	rr := record.RR()

	if rr.TTL/time.Second < 600 {
		rr.TTL = 600 * time.Second
	}

	// record_aux is for MX priority only — use 0 for all other record types
	aux := 0
	if rr.Type == "MX" {
		aux = int(rr.TTL / time.Second)
	}

	// Prepare parameters like PHP script
	params := map[string]interface{}{
		"record_name": rr.Name,
		"record_type": rr.Type,
		"record_data": rr.Data,
		"record_aux":  aux,
		"record_ttl":  int(rr.TTL.Seconds()),
		"zone_host":   strings.TrimSuffix(zone, ".") + ".",
	}

	requestData := map[string]interface{}{
		"kas_login":        p.KasUsername,
		"kas_auth_type":    "plain",
		"kas_auth_data":    p.KasPassword,
		"kas_action":       "add_dns_settings",
		"KasRequestParams": params,
	}
	// JSON encode the entire request like PHP
	jsonData, err := json.Marshal(requestData)
	if err != nil {
		return nil, fmt.Errorf("error encoding JSON: %w", err)
	}

	// Respect KAS flood delay dynamically. Hold kasCallMu for the entire
	// wait+call round trip so concurrent Append/Set/Delete/Get calls can't
	// race past the delay check and flood the API simultaneously.
	kasCallMu.Lock()
	defer kasCallMu.Unlock()
	p.waitForFloodDelay()

	// Call the SOAP method with JSON-encoded params
	res, err := soap.Call("KasApi", gosoap.Params{
		"Params": string(jsonData),
	})
	if err != nil {
		return nil, fmt.Errorf("error calling SOAP method: %w", err)
	}
	if res == nil {
		return nil, fmt.Errorf("response is nil")
	}

	mv, err := mxj.NewMapXml([]byte(res.Body))
	if err != nil {
		return nil, fmt.Errorf("error converting XML to map: %w; raw response: %s", err, res.Body)
	}

	// Check for a SOAP Fault (e.g. record_already_exists, auth errors, flood
	// errors) anywhere in the response, regardless of namespace prefix.
	if faultStr, ok := findFaultString(mv); ok {
		return nil, fmt.Errorf("KAS API error: %s", faultStr)
	}

	// Parse response to check for success and get record ID
	root, ok := mv["KasApiResponse"].(map[string]interface{})
	if !ok {
		return nil, fmt.Errorf("invalid response format: missing KasApiResponse element; raw response: %s", res.Body)
	}

	ret, ok := root["return"].(map[string]interface{})
	if !ok {
		return nil, fmt.Errorf("invalid response format: missing return element; raw response: %s", res.Body)
	}

	// Check for errors in response
	items := ret["item"]
	var itemList []interface{}
	switch v := items.(type) {
	case []interface{}:
		itemList = v
	case map[string]interface{}:
		itemList = []interface{}{v}
	}

	for _, item := range itemList {
		mitem, _ := item.(map[string]interface{})
		keyMap, _ := mitem["key"].(map[string]interface{})
		key, _ := keyMap["#text"].(string)
		if key == "Response" {
			val, _ := mitem["value"].(map[string]interface{})
			// Update flood delay from response
			p.updateFloodDelay(itemList)
			// Extract the new record ID from ReturnInfo
			if recordID, exists := val["ReturnInfo"]; exists {
				if idStr, ok := recordID.(string); ok {
					rr := record.RR()
					ChachedRecords[zone] = append(ChachedRecords[zone], allinklRecord{
						ID:     idStr,
						Name:   rr.Name,
						Type:   rr.Type,
						Value:  rr.Data,
						ZoneID: strings.TrimSuffix(zone, "."),
						TTL:    int(rr.TTL.Seconds()),
					})
				}
			}
		}
	}

	// Return the record with any updates from the server
	// Since the API doesn't return the new record details, we return the original
	return []libdns.Record{record}, nil
}

// getRecordByName looks up a cached record by name and type. This is used by
// SetRecord, where the value of the record is the thing being changed and so
// cannot be used as part of the lookup key.
//
// Note that if a zone legitimately contains multiple records with the same
// name and type (e.g. several TXT records used for ACME challenges), this
// lookup is inherently ambiguous and may return any one of them. Callers
// that need to uniquely identify a specific record (e.g. to delete it)
// should use getRecordByNameTypeValue instead.
func (p *Provider) getRecordByName(ctx context.Context, zone string, record libdns.Record, recursive bool) (allinklRecord, error) {
	rr := record.RR()

	for _, crecord := range ChachedRecords[zone] {
		if crecord.Name == rr.Name && crecord.Type == rr.Type {
			return crecord, nil
		}
	}

	if !recursive {
		p.GetAllRecords(ctx, zone)
		return p.getRecordByName(ctx, zone, record, true)
	}

	return allinklRecord{}, fmt.Errorf("record not found: name=%s type=%s", rr.Name, rr.Type)
}

// getRecordByNameTypeValue looks up a cached record by name, type, AND value.
// Matching on all three fields is required to uniquely identify a record
// when multiple records share the same name and type — for example, two TXT
// records created for parallel ACME "_acme-challenge" validations. Matching
// on name alone (as before) could pick the wrong record and delete/target
// the one that is still needed, breaking ACME validation.
func (p *Provider) getRecordByNameTypeValue(ctx context.Context, zone string, record libdns.Record, recursive bool) (allinklRecord, error) {
	rr := record.RR()

	for _, crecord := range ChachedRecords[zone] {
		if crecord.Name == rr.Name && crecord.Type == rr.Type && crecord.Value == rr.Data {
			return crecord, nil
		}
	}

	if !recursive {
		p.GetAllRecords(ctx, zone)
		return p.getRecordByNameTypeValue(ctx, zone, record, true)
	}

	return allinklRecord{}, fmt.Errorf("record not found: name=%s type=%s data=%s", rr.Name, rr.Type, rr.Data)
}

// SetRecord updates a single DNS record in the specified zone.
func (p *Provider) SetRecord(ctx context.Context, zone string, record libdns.Record) ([]libdns.Record, error) {
	searchedRecord, err := p.getRecordByName(ctx, zone, record, false)
	if err != nil {
		return nil, fmt.Errorf("record not found: %s", record.RR().Name)
	}

	httpClient := &http.Client{
		Timeout: TimeoutTime,
	}

	soap, err := gosoap.SoapClient(ApiBase, httpClient)
	if err != nil {
		return nil, fmt.Errorf("error creating SOAP client: %w", err)
	}

	rr := record.RR()

	if rr.TTL/time.Second < 600 {
		rr.TTL = 600 * time.Second
	}
	ttlInSeconds := int(rr.TTL / time.Second)

	params := map[string]interface{}{
		"record_name": rr.Name,
		"record_type": rr.Type,
		"record_data": rr.Data,
		"record_aux":  ttlInSeconds,
		"record_id":   searchedRecord.ID,
	}
	requestData := map[string]interface{}{
		"kas_login":        p.KasUsername,
		"kas_auth_type":    "plain",
		"kas_auth_data":    p.KasPassword,
		"kas_action":       "update_dns_settings",
		"KasRequestParams": params,
	}

	// JSON encode the entire request like PHP
	jsonData, err := json.Marshal(requestData)
	if err != nil {
		return nil, fmt.Errorf("error encoding JSON: %w", err)
	}

	kasCallMu.Lock()
	defer kasCallMu.Unlock()
	p.waitForFloodDelay()

	// Call the SOAP method with JSON-encoded params
	res, err := soap.Call("KasApi", gosoap.Params{
		"Params": string(jsonData),
	})

	if err != nil {
		return nil, fmt.Errorf("error calling SOAP method: %w", err)
	}
	if res == nil {
		return nil, fmt.Errorf("response is nil")
	}
	mv, err := mxj.NewMapXml([]byte(res.Body))
	if err != nil {
		return nil, fmt.Errorf("error converting XML to map: %w; raw response: %s", err, res.Body)
	}
	// Check for a SOAP Fault anywhere in the response, regardless of
	// namespace prefix.
	if faultStr, ok := findFaultString(mv); ok {
		return nil, fmt.Errorf("KAS API error: %s", faultStr)
	}
	// Parse response to check for success
	root, ok := mv["KasApiResponse"].(map[string]interface{})
	if !ok {
		return nil, fmt.Errorf("invalid response format: missing KasApiResponse element; raw response: %s", res.Body)
	}
	ret, ok := root["return"].(map[string]interface{})
	if !ok {
		return nil, fmt.Errorf("invalid response format: missing return element; raw response: %s", res.Body)
	}

	// Check for errors in response
	items := ret["item"]
	var itemList []interface{}
	switch v := items.(type) {
	case []interface{}:
		itemList = v
	case map[string]interface{}:
		itemList = []interface{}{v}
	}

	for _, item := range itemList {
		mitem, _ := item.(map[string]interface{})
		keyMap, _ := mitem["key"].(map[string]interface{})
		key, _ := keyMap["#text"].(string)
		if key == "Response" {
			p.updateFloodDelay(itemList)
		}
	}

	// If we reach here, the record was successfully updated.
	// Update the cache so subsequent lookups (e.g. a follow-up Delete) see
	// the new value rather than the stale one.
	for i, crecord := range ChachedRecords[zone] {
		if crecord.ID == searchedRecord.ID {
			ChachedRecords[zone][i].Type = rr.Type
			ChachedRecords[zone][i].Value = rr.Data
			ChachedRecords[zone][i].TTL = ttlInSeconds
			break
		}
	}

	updatedRecord := libdns.RR{
		Type: record.RR().Type,
		Name: record.RR().Name,
		Data: record.RR().Data,
		TTL:  record.RR().TTL,
	}

	return []libdns.Record{updatedRecord}, nil
}

// DeleteRecord removes a single DNS record from the specified zone.
func (p *Provider) DeleteRecord(ctx context.Context, zone string, record libdns.Record) ([]libdns.Record, error) {
	// Match on name, type, AND value so that when multiple records share the
	// same name (e.g. two TXT records for parallel ACME challenges), the
	// correct one is deleted instead of an arbitrary match.
	searchedRecord, err := p.getRecordByNameTypeValue(ctx, zone, record, false)
	if err != nil {
		rr := record.RR()
		return nil, fmt.Errorf("record not found: name=%s type=%s data=%s", rr.Name, rr.Type, rr.Data)
	}

	httpClient := &http.Client{
		Timeout: TimeoutTime,
	}

	soap, err := gosoap.SoapClient(ApiBase, httpClient)
	if err != nil {
		return nil, fmt.Errorf("error creating SOAP client: %w", err)
	}
	params := map[string]interface{}{
		"record_id": searchedRecord.ID,
	}
	requestData := map[string]interface{}{
		"kas_login":        p.KasUsername,
		"kas_auth_type":    "plain",
		"kas_auth_data":    p.KasPassword,
		"kas_action":       "delete_dns_settings",
		"KasRequestParams": params,
	}

	// JSON encode the entire request like PHP
	jsonData, err := json.Marshal(requestData)
	if err != nil {
		return nil, fmt.Errorf("error encoding JSON: %w", err)
	}

	kasCallMu.Lock()
	defer kasCallMu.Unlock()
	p.waitForFloodDelay()

	// Call the SOAP method with JSON-encoded params
	res, err := soap.Call("KasApi", gosoap.Params{
		"Params": string(jsonData),
	})

	if err != nil {
		return nil, fmt.Errorf("error calling SOAP method: %w", err)
	}
	if res == nil {
		return nil, fmt.Errorf("response is nil")
	}
	mv, err := mxj.NewMapXml([]byte(res.Body))
	if err != nil {
		return nil, fmt.Errorf("error converting XML to map: %w; raw response: %s", err, res.Body)
	}
	// Check for a SOAP Fault anywhere in the response, regardless of
	// namespace prefix.
	if faultStr, ok := findFaultString(mv); ok {
		return nil, fmt.Errorf("KAS API error: %s", faultStr)
	}
	// Parse response to check for success
	root, ok := mv["KasApiResponse"].(map[string]interface{})
	if !ok {
		return nil, fmt.Errorf("invalid response format: missing KasApiResponse element; raw response: %s", res.Body)
	}
	ret, ok := root["return"].(map[string]interface{})
	if !ok {
		return nil, fmt.Errorf("invalid response format: missing return element; raw response: %s", res.Body)
	}
	// Check for errors in response
	items := ret["item"]
	var itemList []interface{}
	switch v := items.(type) {
	case []interface{}:
		itemList = v
	case map[string]interface{}:
		itemList = []interface{}{v}
	}
	for _, item := range itemList {
		mitem, _ := item.(map[string]interface{})
		keyMap, _ := mitem["key"].(map[string]interface{})
		key, _ := keyMap["#text"].(string)
		if key == "Response" {
			p.updateFloodDelay(itemList)
		}
	}
	// If we reach here, the record was successfully deleted
	deletedRecord := libdns.RR{
		Type: record.RR().Type,
		Name: record.RR().Name,
		Data: record.RR().Data,
		TTL:  record.RR().TTL,
	}
	// Remove the record from the cache
	for i, crecord := range ChachedRecords[zone] {
		if crecord.ID == searchedRecord.ID {
			ChachedRecords[zone] = append(ChachedRecords[zone][:i], ChachedRecords[zone][i+1:]...)
			break
		}
	}
	return []libdns.Record{deletedRecord}, nil

}
