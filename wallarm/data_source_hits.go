package wallarm

import (
	"fmt"
	"time"

	"github.com/wallarm/wallarm-go"

	"github.com/hashicorp/terraform-plugin-sdk/helper/schema"
)

// nonAttackHitTypes lists hit types excluded from the data source output.
// These match the !type API filter to ensure only attack-relevant hits are returned.
var nonAttackHitTypes = map[string]bool{
	"warn":     true,
	"infoleak": true,
}

// hitActionSchema is a computed-only variant of defaultResourceRuleActionSchema
// used within each hit entry in the data source. The Set hash function matches
// the one used by ResourceRuleWallarmRead so the output is directly usable as
// an action block in wallarm_rule_* resources.
var hitActionSchema = &schema.Schema{
	Type:     schema.TypeSet,
	Computed: true,
	Elem: &schema.Resource{
		Schema: map[string]*schema.Schema{
			"type": {
				Type:     schema.TypeString,
				Computed: true,
			},
			"value": {
				Type:     schema.TypeString,
				Computed: true,
			},
			"point": {
				Type:     schema.TypeMap,
				Computed: true,
				Elem:     &schema.Schema{Type: schema.TypeString},
			},
		},
	},
}

func dataSourceWallarmHits() *schema.Resource {
	return &schema.Resource{
		Read: dataSourceWallarmHitsRead,

		Schema: map[string]*schema.Schema{
			"client_id": {
				Type:     schema.TypeInt,
				Required: true,
			},
			"request_id": {
				Type:     schema.TypeString,
				Required: true,
			},
			// time accepts exactly two Unix timestamps: [from, to].
			// Defaults to the last 30 days when omitted.
			"time": {
				Type:     schema.TypeList,
				Optional: true,
				MinItems: 2,
				MaxItems: 2,
				Elem:     &schema.Schema{Type: schema.TypeInt},
			},
			"hits": {
				Type:     schema.TypeList,
				Computed: true,
				Elem: &schema.Resource{
					Schema: map[string]*schema.Schema{
						"id": {
							Type:     schema.TypeList,
							Computed: true,
							Elem:     &schema.Schema{Type: schema.TypeString},
						},
						"type": {
							Type:     schema.TypeString,
							Computed: true,
						},
						"ip": {
							Type:     schema.TypeString,
							Computed: true,
						},
						"size": {
							Type:     schema.TypeInt,
							Computed: true,
						},
						"statuscode": {
							Type:     schema.TypeInt,
							Computed: true,
						},
						"time": {
							Type:     schema.TypeInt,
							Computed: true,
						},
						"value": {
							Type:     schema.TypeString,
							Computed: true,
						},
						"impression": {
							Type:     schema.TypeString,
							Computed: true,
						},
						"stamps": {
							Type:     schema.TypeList,
							Computed: true,
							Elem:     &schema.Schema{Type: schema.TypeInt},
						},
						"stamps_hash": {
							Type:     schema.TypeInt,
							Computed: true,
						},
						"regex": {
							Type:     schema.TypeList,
							Computed: true,
							Elem:     &schema.Schema{Type: schema.TypeString},
						},
						"response_time": {
							Type:     schema.TypeInt,
							Computed: true,
						},
						"remote_country": {
							Type:     schema.TypeString,
							Computed: true,
						},
						// point is the request location where the attack was found
						// (e.g. ["post", "form_urlencoded", "param"]).
						// Use this directly as the point argument in wallarm_rule_disable_stamp.
						"point": {
							Type:     schema.TypeList,
							Computed: true,
							Elem:     &schema.Schema{Type: schema.TypeString},
						},
						"remote_port": {
							Type:     schema.TypeInt,
							Computed: true,
						},
						"poolid": {
							Type:     schema.TypeInt,
							Computed: true,
						},
						"ip_blocked": {
							Type:     schema.TypeBool,
							Computed: true,
						},
						"experimental": {
							Type:     schema.TypeString,
							Computed: true,
						},
						"wallarm_scanner": {
							Type:     schema.TypeString,
							Computed: true,
						},
						"attackid": {
							Type:     schema.TypeList,
							Computed: true,
							Elem:     &schema.Schema{Type: schema.TypeString},
						},
						"block_status": {
							Type:     schema.TypeString,
							Computed: true,
						},
						"request_id": {
							Type:     schema.TypeString,
							Computed: true,
						},
						"datacenter": {
							Type:     schema.TypeString,
							Computed: true,
						},
						"proxy_type": {
							Type:     schema.TypeString,
							Computed: true,
						},
						"tor": {
							Type:     schema.TypeString,
							Computed: true,
						},
						"state": {
							Type:     schema.TypeString,
							Computed: true,
						},
						"known_attack": {
							Type:     schema.TypeList,
							Computed: true,
							Elem:     &schema.Schema{Type: schema.TypeString},
						},
						"known_false": {
							Type:     schema.TypeString,
							Computed: true,
						},
						"protocol": {
							Type:     schema.TypeString,
							Computed: true,
						},
						"auth_protocol": {
							Type:     schema.TypeList,
							Computed: true,
							Elem:     &schema.Schema{Type: schema.TypeString},
						},
						"endpoint_id": {
							Type:     schema.TypeString,
							Computed: true,
						},
						"path": {
							Type:     schema.TypeString,
							Computed: true,
						},
						"domain": {
							Type:     schema.TypeString,
							Computed: true,
						},
						"node_uuid": {
							Type:     schema.TypeList,
							Computed: true,
							Elem:     &schema.Schema{Type: schema.TypeString},
						},
						"compromised_logins": {
							Type:     schema.TypeList,
							Computed: true,
							Elem:     &schema.Schema{Type: schema.TypeString},
						},
						"ebpf": {
							Type:     schema.TypeString,
							Computed: true,
						},
						"aasm_event": {
							Type:     schema.TypeBool,
							Computed: true,
						},
						"api_spec_violation": {
							Type:     schema.TypeString,
							Computed: true,
						},
						"api_spec_id": {
							Type:     schema.TypeString,
							Computed: true,
						},
						// action contains rule conditions derived from the hit's path, domain,
						// and poolid fields. Use this as the action block in wallarm_rule_disable_stamp
						// to scope the rule to the same endpoint that produced the hit.
						"action": hitActionSchema,
					},
				},
			},
		},
	}
}

func dataSourceWallarmHitsRead(d *schema.ResourceData, m interface{}) error {
	client := m.(wallarm.API)
	clientID := d.Get("client_id").(int)
	requestID := d.Get("request_id").(string)

	// Build the time filter: use provided timestamps or default to last 30 days.
	var timeFilter [][]int64
	if v, ok := d.GetOk("time"); ok {
		timeList := v.([]interface{})
		if len(timeList) == 2 {
			from := int64(timeList[0].(int))
			to := int64(timeList[1].(int))
			timeFilter = [][]int64{{from, to}}
		}
	}
	if timeFilter == nil {
		now := time.Now().Unix()
		timeFilter = [][]int64{{now - 30*24*60*60, now}}
	}

	req := &wallarm.GetHitsRead{
		Filter: &wallarm.GetHitsFilter{
			// State and SecurityIssueID are nil (marshals as JSON null).
			NotType:           []string{"warn", "infoleak"},
			Time:              timeFilter,
			NotState:          "falsepositive",
			Clientid:          clientID,
			NotExperimental:   true,
			NotAasmEvent:      true,
			NotWallarmScanner: true,
			RequestID:         requestID,
		},
		Limit:     200,
		Offset:    0,
		OrderBy:   "time",
		OrderDesc: true,
	}

	apiHits, err := client.GetHitsRead(req)
	if err != nil {
		return err
	}

	hits := make([]interface{}, 0, len(apiHits))
	for _, h := range apiHits {
		// Client-side guard: skip any hit types that should not be returned.
		if nonAttackHitTypes[h.Type] {
			continue
		}

		hitMap := map[string]interface{}{
			"id":              stringsOrEmpty(h.ID),
			"type":            h.Type,
			"ip":              h.IP,
			"size":            h.Size,
			"statuscode":      h.Statuscode,
			"time":            int(h.Time),
			"value":           h.Value,
			"impression":      interfaceToStringOrEmpty(h.Impression),
			"stamps":          intsToInterface(h.Stamps),
			"stamps_hash":     h.StampsHash,
			"regex":           interfaceSliceToStrings(h.Regex),
			"response_time":   h.ResponseTime,
			"remote_country":  interfaceToStringOrEmpty(h.RemoteCountry),
			"point":           stringsOrEmpty(h.Point),
			"remote_port":     h.RemotePort,
			"poolid":          h.Poolid,
			"ip_blocked":      h.IPBlocked,
			"experimental":    interfaceToStringOrEmpty(h.Experimental),
			"wallarm_scanner": interfaceToStringOrEmpty(h.WallarmScanner),
			"attackid":        stringsOrEmpty(h.AttackID),
			"block_status":    h.BlockStatus,
			"request_id":      h.RequestID,
			"datacenter":      h.Datacenter,
			"proxy_type":      interfaceToStringOrEmpty(h.ProxyType),
			"tor":             h.Tor,
			"state":           interfaceToStringOrEmpty(h.State),
			"known_attack":    stringsOrEmpty(h.KnownAttack),
			"known_false":     interfaceToStringOrEmpty(h.KnownFalse),
			"protocol":        h.Protocol,
			"auth_protocol":   stringsOrEmpty(h.AuthProtocol),
			"endpoint_id":     interfaceToStringOrEmpty(h.EndpointID),
			"path":            h.Path,
			"domain":          h.Domain,
			"node_uuid":       stringsOrEmpty(h.NodeUUID),
			"compromised_logins": interfaceSliceToStrings(h.CompromisedLogins),
			"ebpf":            interfaceToStringOrEmpty(h.Ebpf),
			"aasm_event":      h.AasmEvent,
			"api_spec_violation": interfaceToStringOrEmpty(h.APISpecViolation),
			"api_spec_id":     interfaceToStringOrEmpty(h.APISpecID),
			"action":          HitToActionSet(h.Path, h.Domain, h.Poolid),
		}

		hits = append(hits, hitMap)
	}

	d.SetId(fmt.Sprintf("hits_%d_%s", clientID, requestID))

	if err := d.Set("hits", hits); err != nil {
		return fmt.Errorf("error setting hits: %s", err)
	}
	return nil
}

// stringsOrEmpty converts a []string to []interface{}, returning an empty slice
// when the input is nil so the Terraform SDK never receives a nil list.
func stringsOrEmpty(ss []string) []interface{} {
	result := make([]interface{}, len(ss))
	for i, s := range ss {
		result[i] = s
	}
	return result
}

// intsToInterface converts []int to []interface{} for TypeList of TypeInt.
func intsToInterface(ints []int) []interface{} {
	result := make([]interface{}, len(ints))
	for i, v := range ints {
		result[i] = v
	}
	return result
}

// interfaceSliceToStrings converts []interface{} to []interface{} of strings,
// formatting each element with fmt.Sprintf so that non-string values are preserved.
func interfaceSliceToStrings(in []interface{}) []interface{} {
	result := make([]interface{}, 0, len(in))
	for _, v := range in {
		if v == nil {
			continue
		}
		result = append(result, fmt.Sprintf("%v", v))
	}
	return result
}

// interfaceToStringOrEmpty converts a nullable interface{} value (from JSON null)
// to a string. Returns an empty string when the value is nil.
func interfaceToStringOrEmpty(v interface{}) string {
	if v == nil {
		return ""
	}
	return fmt.Sprintf("%v", v)
}
