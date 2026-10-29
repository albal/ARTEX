package agent

import (
	"context"
	"encoding/json"
	"fmt"
	"net"
	"net/url"
	"strconv"
	"strings"

	"github.com/Autumn-27/artex/db"
	actool "github.com/Autumn-27/norma/tool"
)

// assetInterceptCandidates extracts the domain/IP/URL candidate strings of one asset input to be inserted, for asset interception matching.
// A URL's host is split out and classified, so that a service/endpoint asset "carrying only a URL" can also be matched by domain/IP rules.
func assetInterceptCandidates(item assetInputItem) (domains, ips, urls []string) {
	add := func(dst *[]string, s string) {
		if s = strings.TrimSpace(s); s != "" {
			*dst = append(*dst, s)
		}
	}
	add(&domains, item.Domain)
	for _, d := range item.BoundDomains {
		add(&domains, d)
	}
	add(&ips, item.IP)
	add(&ips, item.ServiceIP)
	add(&urls, item.URL)
	if item.URL != "" {
		if u, err := url.Parse(item.URL); err == nil {
			if h := u.Hostname(); h != "" {
				if net.ParseIP(h) != nil {
					add(&ips, h)
				} else {
					add(&domains, h)
				}
			}
		}
	}
	return domains, ips, urls
}

// assetInputLabel returns a short identifier for one asset to be inserted, used in interception messages.
func assetInputLabel(item assetInputItem) string {
	typ := strings.TrimSpace(item.Type)
	var target string
	switch {
	case strings.TrimSpace(item.Domain) != "":
		target = strings.TrimSpace(item.Domain)
	case strings.TrimSpace(item.URL) != "":
		target = strings.TrimSpace(item.URL)
	case strings.TrimSpace(item.IP) != "":
		target = strings.TrimSpace(item.IP)
	case strings.TrimSpace(item.ServiceIP) != "":
		target = strings.TrimSpace(item.ServiceIP)
	default:
		target = "(unknown)"
	}
	if typ != "" {
		return fmt.Sprintf("[%s] %s", typ, target)
	}
	return target
}

// =====================================================================
// Unified asset insertion tools
// =====================================================================

// SetAssetStore wires the asset store and company store onto this ToolSet
// so the insert_assets, add_company_scope, and list_assets tools are active.
func (t *ToolSet) SetAssetStore(as *db.AssetStore, cs *db.CompanyStore) {
	t.as = as
	t.cs = cs
}

// assetInputItem is one element of the insert_assets "assets" array.
type assetInputItem struct {
	Type string `json:"type"` // root_domain|ip|subdomain|app|service|endpoint

	// ---- root_domain / subdomain ----
	Domain      string   `json:"domain"`
	ICP         string   `json:"icp"`
	RecordType  string   `json:"record_type"`
	RecordValue []string `json:"record_value"`

	// ---- ip ----
	IP           string           `json:"ip"`
	BoundDomains []string         `json:"bound_domains"`
	OpenPorts    []db.PortService `json:"open_ports"`

	// ---- app ----
	AppName     string `json:"app_name"`
	BundleID    string `json:"bundle_id"`
	Category    string `json:"category"`
	Description string `json:"description"`
	AppICP      string `json:"app_icp"`
	CompanyID   *int64 `json:"company_id"` // explicit company link (app only; others auto-attribute via scope)

	// ---- service (http) ----
	URL           string           `json:"url"`
	Technologies  []string         `json:"technologies"`
	StatusCode    *int             `json:"status_code"`
	ContentLength *int64           `json:"content_length"`
	PageTitle     string           `json:"page_title"`
	FaviconMMH3   string           `json:"favicon_mmh3"`
	Auth          []map[string]any `json:"auth"`
	ServiceName   string           `json:"service_name"`
	ServiceIP     string           `json:"service_ip"` // optional enrichment IP

	// ---- service (other) ----
	Port  int    `json:"port"`
	Proto string `json:"proto"`

	// ---- endpoint ----
	Method string           `json:"method"`
	Params []map[string]any `json:"params"`
}

// insertAssets is the unified insert_assets agent tool.
func (t *ToolSet) insertAssets() actool.CoreTool {
	return writeTool(
		"insert_assets",
		"Bulk-register newly discovered assets; one call can mix several types (see the type enum).\n"+
			"Required fields per type: root_domain→domain; ip→ip (must be IPv4/IPv6, not a hostname); subdomain→domain; app→app_name; service(HTTP)→url; service(non-HTTP)→service_name+port (at least one of ip/domain); endpoint→url+method. See each field's description for the rest.\n"+
			"auth/technologies/params are append-merged, not overwriting the original.\n"+
			"Returns: {results:[{index,id,type}], errors:[{index,error}]}",
		obj(map[string]any{
			// task_id is not exposed to the model: which task a worker belongs to is authoritatively assigned by the program via SetTaskID (see handler).
			"assets": map[string]any{
				"type":        "array",
				"description": "the asset array, each element one asset record",
				"items": obj(map[string]any{
					"type": map[string]any{
						"type":        "string",
						"enum":        []string{"root_domain", "ip", "subdomain", "app", "service", "endpoint"},
						"description": "asset type",
					},
					// root_domain / subdomain
					"domain":      str("root domain or subdomain (required for root_domain/subdomain)"),
					"icp":         str("ICP record number (optional)"),
					"record_type": str("DNS record type: A/AAAA/CNAME/MX etc. (optional for subdomain)"),
					"record_value": map[string]any{
						"type":        "array",
						"items":       map[string]any{"type": "string"},
						"description": "list of DNS resolution values (optional for subdomain, e.g. [\"1.2.3.4\",\"2.3.4.5\"])",
					},
					// ip
					"ip": str("IP address, must be an IPv4/IPv6 address, not a hostname (for a hostname use the domain field with type=subdomain); required for the ip type; optional for service/endpoint, used to link the IP"),
					"bound_domains": map[string]any{
						"type":        "array",
						"items":       map[string]any{"type": "string"},
						"description": "list of domains bound to this IP (optional for the ip type)",
					},
					"open_ports": map[string]any{
						"type":        "array",
						"description": "list of open ports (optional for the ip type)",
						"items": obj(map[string]any{
							"port":    intp("port number"),
							"service": str("service name, e.g. http/ssh/mysql etc. (optional)"),
						}, "port"),
					},
					// app
					"app_name":    str("application name (required for the app type)"),
					"bundle_id":   str("Bundle ID (optional for the app type)"),
					"category":    str("application category (optional)"),
					"description": str("application description (optional)"),
					"app_icp":     str("application ICP record (optional)"),
					"company_id":  intp("owning company id (optional for the app type; an app cannot be attributed automatically by scope, so specify it explicitly. The id is returned by add_company_scope)"),
					// service (http)
					"url":         str("full URL, including scheme and port (required for an HTTP service; service_type is set to http automatically)"),
					"status_code": intp("HTTP response status code, e.g. 200/301/403/404 (optional)"),
					"content_length": map[string]any{
						"type":        "integer",
						"description": "HTTP response body size in bytes (optional)",
					},
					"page_title":   str("the page <title> content (optional)"),
					"favicon_mmh3": str("favicon MMH3 hash (optional)"),
					"technologies": map[string]any{
						"type":        "array",
						"items":       map[string]any{"type": "string"},
						"description": "list of fingerprints/tech stack, e.g. [\"Nginx\",\"Vue\",\"Bootstrap\"] (optional)",
					},
					"auth": map[string]any{
						"type":        "array",
						"description": "list of discovered authentication information, each with type/username/password etc. (optional, append not overwrite)",
						"items":       map[string]any{"type": "object"},
					},
					// service (other, non-HTTP)
					"service_name": str("service name, e.g. ssh/mysql/redis (required for a non-HTTP service)"),
					"port":         intp("port number (required for a non-HTTP service)"),
					// endpoint
					"method": str("HTTP method: GET/POST/PUT/PATCH/DELETE etc. (required for endpoint)"),
					"params": map[string]any{
						"type":        "array",
						"description": "list of request parameters, each with location(query/body/header/path)/name/value/type (optional, append not overwrite)",
						"items":       map[string]any{"type": "object"},
					},
				}, "type"),
			},
		}, "assets"),
		func(_ context.Context, in json.RawMessage) (actool.Result, error) {
			if t.as == nil {
				return actool.Errorf("insert_assets not enabled: AssetStore not initialised"), nil
			}
			var a struct {
				Assets []assetInputItem `json:"assets"`
			}
			if err := json.Unmarshal(in, &a); err != nil {
				return actool.Errorf("invalid input: " + err.Error()), nil
			}
			// task_id is authoritatively assigned by the program (worker: SetTaskID) and not accepted from the model, to avoid the model omitting/mis-passing it
			// and leaving assets unattributed or attributed to the wrong task. For callers with no task context (auto/pentest/chat), t.taskID=0.
			taskID := t.taskID

			type result struct {
				Index int    `json:"index"`
				ID    int64  `json:"id"`
				Type  string `json:"type"`
			}
			type errEntry struct {
				Index int    `json:"index"`
				Error string `json:"error"`
			}

			var results []result
			var errs []errEntry

			// the asset gate rules are loaded once; if the read fails the check is skipped (insertion is not blocked).
			// intercept rules = global ∪ task-level block; allow rules = task-level allow.
			blockRules, _ := t.as.ListAssetInterceptRules()
			var allowRules []db.AssetInterceptRule
			if t.taskID > 0 {
				if tb, ta, err := t.as.TaskInterceptRulesSplit(t.taskID); err == nil {
					blockRules = append(blockRules, tb...)
					allowRules = ta
				}
			}

			for i, item := range a.Assets {
				// asset gate: block first then allow; a rejected asset must not be inserted (skip Upsert and later side effects).
				domains, ips, urls := assetInterceptCandidates(item)
				if d := db.EvaluateAssetGate(blockRules, allowRules, domains, ips, urls); !d.Allowed {
					errs = append(errs, errEntry{
						Index: i,
						Error: fmt.Sprintf("asset %s %s, insertion forbidden", assetInputLabel(item), d.Reason),
					})
					continue
				}

				typ := strings.TrimSpace(item.Type)
				var id int64
				var err error

				switch typ {
				case "root_domain":
					id, err = t.as.UpsertRootDomain(db.UpsertRootDomainReq{
						Domain: item.Domain,
						ICP:    item.ICP,
						TaskID: taskID,
					})

				case "ip":
					id, err = t.as.UpsertIP(db.UpsertIPReq{
						IP:           item.IP,
						BoundDomains: item.BoundDomains,
						OpenPorts:    item.OpenPorts,
						TaskID:       taskID,
					})

				case "subdomain":
					id, err = t.as.UpsertSubdomain(db.UpsertSubdomainReq{
						Domain:      item.Domain,
						RecordType:  item.RecordType,
						RecordValue: item.RecordValue,
						ICP:         item.ICP,
						TaskID:      taskID,
					})

				case "app":
					id, err = t.as.UpsertApp(db.UpsertAppReq{
						Name:        item.AppName,
						BundleID:    item.BundleID,
						Category:    item.Category,
						Description: item.Description,
						ICP:         item.AppICP,
						CompanyID:   item.CompanyID,
						TaskID:      taskID,
					})

				case "service":
					// distinguish HTTP vs other by presence of url
					if item.URL != "" {
						// agent may send "ip" or "service_ip" for the enrichment IP; accept both
						svcIP := item.ServiceIP
						if svcIP == "" {
							svcIP = item.IP
						}
						id, err = t.as.UpsertHTTPService(db.UpsertHTTPServiceReq{
							URL:           item.URL,
							Technologies:  item.Technologies,
							StatusCode:    item.StatusCode,
							ContentLength: item.ContentLength,
							PageTitle:     item.PageTitle,
							FaviconMMH3:   item.FaviconMMH3,
							Auth:          item.Auth,
							IP:            svcIP,
							TaskID:        taskID,
						})
					} else {
						id, err = t.as.UpsertOtherService(db.UpsertOtherServiceReq{
							Domain:      item.Domain,
							IP:          item.IP,
							Port:        item.Port,
							ServiceName: item.ServiceName,
							Auth:        item.Auth,
							TaskID:      taskID,
						})
					}

				case "endpoint":
					id, err = t.as.UpsertEndpoint(db.UpsertEndpointReq{
						URL:    item.URL,
						Method: item.Method,
						Params: item.Params,
						IP:     item.ServiceIP,
						TaskID: taskID,
					})

				default:
					errs = append(errs, errEntry{Index: i, Error: "unknown type: " + typ})
					continue
				}

				if err != nil {
					errs = append(errs, errEntry{Index: i, Error: err.Error()})
					continue
				}
				results = append(results, result{Index: i, ID: id, Type: typ})
				t.writes.Assets++
				t.anchorOwner(id)
				if taskID > 0 {
					var sourceNodeID *int64
					if t.ownerNode > 0 {
						nodeID := t.ownerNode
						sourceNodeID = &nodeID
					}
					summary := "registered by an agent via insert_assets"
					if t.ownerNode > 0 {
						summary = fmt.Sprintf("registered by worker intent #%d via insert_assets", t.ownerNode)
					}
					_ = t.as.SetTaskAssetSource(taskID, id, "agent", summary, sourceNodeID)
				}
				// automatically brought into the test scope (source='auto'): only for the item the worker explicitly inserted at the top level,
				// adding a conservative scope by its type; assets derived as side effects do not go through here, so the scope is not blindly widened. No-op when taskID=0.
				// independent of the coverage toggle: task_scope is the task's scope boundary (the filter basis for list/query),
				// and the coverage toggle only decides whether to use it as the denominator for metrics, not whether to accumulate the scope itself.
				{
					svcIP := item.ServiceIP
					if svcIP == "" {
						svcIP = item.IP
					}
					_ = t.as.AddAutoScope(taskID, typ, item.Domain, item.URL, svcIP)
				}
			}

			return jsonResult(map[string]any{
				"results": results,
				"errors":  errs,
			})
		},
	)
}

// addCompanyScope writes to company_scope table and triggers asset attribution.
func (t *ToolSet) addCompanyScope() actool.CoreTool {
	return writeTool(
		"add_company_scope",
		"Add a domain/IP/CIDR/ICP record/company keyword to a company's [asset scope] — domains, networks and ICP records automatically claim the assets they match, while keywords are only provided to the agent as a scope hint.\n"+
			"The company name is unique: if company does not exist it is created, if it exists it is reused (only the scope is merged in).\n"+
			"scope is one per line, auto-detected by the system: root domain / URL / single IP / CIDR range / ICP record / company keyword.\n"+
			"Always give reason to explain the basis for attribution (whois/certificate/ASN etc.).\n"+
			"Guardrails: a bare TLD and overly broad ranges are rejected (an IPv4 prefix must be /16-/32, an IPv6 prefix /32-/128); invalid lines are skipped and returned in errors.",
		obj(map[string]any{
			"company": str("company name (created if it does not exist, reused if it does; the name is unique)"),
			"scope":   str("asset scope, one per line: domain / URL / IP / CIDR / ICP record / company keyword"),
			"reason":  str("basis for attribution (evidence/source), must be filled in"),
			"logo":    str("company logo URL (optional; only takes effect when creating a new company)"),
		}, "company", "scope"),
		func(_ context.Context, in json.RawMessage) (actool.Result, error) {
			if t.cs == nil {
				return actool.Errorf("add_company_scope not enabled: CompanyStore not initialised"), nil
			}
			var a struct {
				Company string `json:"company"`
				Scope   string `json:"scope"`
				Reason  string `json:"reason"`
				Logo    string `json:"logo"`
			}
			if err := json.Unmarshal(in, &a); err != nil {
				return actool.Errorf(err.Error()), nil
			}
			if strings.TrimSpace(a.Company) == "" {
				return actool.Errorf("company must not be empty"), nil
			}
			companyID, _, err := t.cs.UpsertCompany(a.Company, a.Logo)
			if err != nil {
				return actool.Errorf("failed to create/get company: " + err.Error()), nil
			}
			lines := splitLines(a.Scope)
			added, skipped, invalid, errMsgs := t.cs.AddScope(companyID, lines, a.Reason)
			out := map[string]any{
				"company_id": companyID,
				"added":      added,
				"skipped":    skipped,
				"invalid":    invalid,
			}
			if len(errMsgs) > 0 {
				out["errors"] = errMsgs
			}
			return jsonResult(out)
		},
	)
}

// addTaskScope lets the plan agent add test scope to THE CURRENT TASK — the coverage
// denominator and the task's authorization edge. Worker discoveries are auto-scoped
// (precise host) by insertAssets; this tool is for DELIBERATELY WIDENING: pull a whole
// root domain or whole company into scope, or add a specific subdomain / ip.
func (t *ToolSet) addTaskScope() actool.CoreTool {
	return writeTool(
		"add_task_scope",
		"Add a test scope to [this task] — this is the task's authorisation boundary and the denominator of asset test coverage.\n"+
			"kind supports: company (all assets under a company name) / root_domain (the whole root domain, including all subdomains) / subdomain (a single exact subdomain) / ip / cidr / icp / keyword.\n"+
			"Note: hosts the worker meets one by one are [automatically] added to the scope (exact subdomain); this tool is for [actively widening] — bringing in a whole root domain/whole company, or adding a specified subdomain/IP.\n"+
			"value: for company pass the company name or id (the company must already exist); for root_domain/subdomain pass the domain; for ip/cidr pass the IP or range; for icp/keyword pass the record number or company keyword.\n"+
			"Always give reason to explain the basis (auditable). Use the entries array for several.",
		obj(map[string]any{
			"entries": map[string]any{"type": "array", "description": "batch: [{kind, value}]. kind ∈ company/root_domain/subdomain/ip/cidr/icp/keyword.", "items": map[string]any{"type": "object"}},
			"kind":    str("[single] company / root_domain / subdomain / ip / cidr / icp / keyword"),
			"value":   str("[single] company name or id / domain / IP / CIDR / ICP / keyword"),
			"reason":  str("basis for adding (for auditing), must be filled in"),
		}),
		func(_ context.Context, in json.RawMessage) (actool.Result, error) {
			if t.as == nil {
				return actool.Errorf("add_task_scope not enabled: AssetStore not initialised"), nil
			}
			if t.taskID <= 0 {
				return actool.Errorf("add_task_scope requires task context (no task currently)"), nil
			}
			type scopeEntry struct {
				Kind  string `json:"kind"`
				Value string `json:"value"`
			}
			var a struct {
				Entries    []scopeEntry `json:"entries"`
				scopeEntry              // single mode
				Reason     string       `json:"reason"`
			}
			_ = json.Unmarshal(in, &a)
			items := a.Entries
			if len(items) == 0 {
				items = []scopeEntry{a.scopeEntry}
			}
			var added []map[string]any
			errs := map[string]string{}
			for i, e := range items {
				ts, err := t.as.AddAgentScope(t.taskID, strings.TrimSpace(e.Kind), e.Value, a.Reason, "agent")
				if err != nil {
					errs[strconv.Itoa(i)] = err.Error()
					continue
				}
				added = append(added, map[string]any{"kind": ts.Kind, "domain": ts.Domain, "net": ts.Net, "value": ts.Value, "company_id": ts.CompanyID})
			}
			out := map[string]any{"added": added}
			if len(errs) > 0 {
				out["errors"] = errs
			}
			return jsonResult(out)
		},
	)
}

// listUntestedAssets lets the plan agent pull the current + directly inherited
// scope's not-yet-tested assets on demand (filter by type, paginated).
func (t *ToolSet) listUntestedAssets() actool.CoreTool {
	return readTool(
		"list_untested_assets",
		"Query assets within the scope of [this task and directly related tasks] that are not yet covered by a fact anchor (the related scope is read-only, for you to judge whether to test more, not a substitute for your decision).\n"+
			"Optionally filter by asset type: root_domain/subdomain/service/app/endpoint/ip.\n"+
			"Paging: page starts at 1, page_size defaults to 10. Returns {assets:[{id,type,label}], total, page, page_size}. Only available in task context.",
		obj(map[string]any{
			"type":      str("asset type filter (optional): root_domain/subdomain/service/app/endpoint/ip"),
			"page":      intp("page number, starting at 1 (default 1)"),
			"page_size": intp("items per page (default 10)"),
		}),
		func(_ context.Context, in json.RawMessage) (actool.Result, error) {
			if t.as == nil {
				return actool.Errorf("list_untested_assets not enabled: AssetStore not initialised"), nil
			}
			if t.taskID <= 0 || t.ts == nil {
				return actool.Errorf("list_untested_assets requires task context"), nil
			}
			var a struct {
				Type     string `json:"type"`
				Page     int    `json:"page"`
				PageSize int    `json:"page_size"`
			}
			_ = json.Unmarshal(in, &a)
			if a.Page <= 0 {
				a.Page = 1
			}
			if a.PageSize <= 0 {
				a.PageSize = 10
			}
			offset := (a.Page - 1) * a.PageSize
			assets, total, err := t.as.ListUntestedAssetsWithSources(t.taskID, strings.TrimSpace(a.Type), a.PageSize, offset)
			if err != nil {
				return actool.Errorf(err.Error()), nil
			}
			return jsonResult(map[string]any{
				"assets": assets, "total": total, "page": a.Page, "page_size": a.PageSize,
			})
		},
	)
}

// listAssets lets an agent query the asset table.
func (t *ToolSet) listAssets() actool.CoreTool {
	return readTool(
		"list_assets",
		"Query the asset store: search by a DSL expression, or fetch directly by id/ids; paging supported. Returns only assets within the test scope of [this task and directly related tasks].\n"+
			"DSL: field=value fuzzy (ILIKE) | field==value exact | field!=value exclude | numeric fields support > >= < <= | a bare word = full-text fuzzy; combine with AND/OR (AND has higher precedence), group with parentheses. Asset type uses the separate type parameter, not written into the DSL.\n"+
			"When id/ids are not passed, dsl must be non-empty (an unconditional full query is not allowed).\n"+
			"Available fields: domain (root/sub/service domain), root_domain, ip, url, page_title, icp, service_name, app_name, method (e.g. GET/POST), service_type (http|other), record_type (e.g. A/CNAME), technology (array, = fuzzy == exact), port/status_code/company_id (integer).\n"+
			"Examples: status_code>=400 AND technology=shiro ; (port==80 OR port==443) AND technology=nginx",
		obj(map[string]any{
			"dsl":    str(`DSL query expression (see the tool description for syntax/fields). Must be non-empty when id/ids are not passed.`),
			"type":   str("asset type filter: root_domain|ip|subdomain|app|service|endpoint (a separate field, can be combined with dsl; type alone is not enough to query, dsl is still required)"),
			"id":     intp("fetch directly by a single asset id (optional, mutually exclusive with dsl/type)"),
			"ids":    map[string]any{"type": "array", "items": map[string]any{"type": "integer"}, "description": "fetch directly by several asset ids (optional, mutually exclusive with dsl/type)"},
			"limit":  intp("return limit, default 10 (optional)"),
			"offset": intp("paging offset, default 0 (optional)"),
		}),
		func(_ context.Context, in json.RawMessage) (actool.Result, error) {
			if t.as == nil {
				return actool.Errorf("list_assets not enabled: AssetStore not initialised"), nil
			}
			var a struct {
				DSL    string  `json:"dsl"`
				Type   string  `json:"type"`
				ID     int64   `json:"id"`
				IDs    []int64 `json:"ids"`
				Limit  int     `json:"limit"`
				Offset int     `json:"offset"`
			}
			_ = json.Unmarshal(in, &a)
			if a.Limit <= 0 {
				a.Limit = 10
			}

			var assets []*db.Asset
			var err error
			switch {
			case a.ID > 0:
				assets, err = t.as.GetByIDsInScope(t.taskID, []int64{a.ID})
			case len(a.IDs) > 0:
				assets, err = t.as.GetByIDsInScope(t.taskID, a.IDs)
			case a.DSL != "":
				assets, err = t.as.QueryDSLInScope(a.DSL, a.Type, t.taskID, a.Limit, a.Offset)
			default:
				return actool.Errorf("dsl must not be empty when id/ids are not passed: an unconditional query of all assets is not allowed, please provide query conditions"), nil
			}
			if err != nil {
				return actool.Errorf("DSL error: " + err.Error()), nil
			}
			return jsonResult(map[string]any{
				"count":  len(assets),
				"assets": assets,
			})
		},
	)
}

// listCompanies lets an agent enumerate companies with their scope + asset count.
func (t *ToolSet) listCompanies() actool.CoreTool {
	return readTool(
		"list_companies",
		"List the [companies] in the asset store with their asset scope and the number of assets attributed to each. Used to see which companies exist and "+
			"to get a company_id (used when insert_assets links an app, or list_assets filters by company_id). "+
			"Optional search filters by company name (fuzzy, case-insensitive); leave empty to return all.",
		obj(map[string]any{
			"search": str("filter by company name (optional, case-insensitive, fuzzy); leave empty to return all"),
		}),
		func(_ context.Context, in json.RawMessage) (actool.Result, error) {
			if t.cs == nil {
				return actool.Errorf("list_companies not enabled: CompanyStore not initialised"), nil
			}
			var a struct {
				Search string `json:"search"`
			}
			_ = json.Unmarshal(in, &a)
			cos, err := t.cs.ListCompanies()
			if err != nil {
				return actool.Errorf("failed to query companies: " + err.Error()), nil
			}
			q := strings.ToLower(strings.TrimSpace(a.Search))
			type companyOut struct {
				ID         int64    `json:"id"`
				Name       string   `json:"name"`
				AssetCount int      `json:"asset_count"`
				Scope      []string `json:"scope"`
			}
			out := make([]companyOut, 0, len(cos))
			for _, c := range cos {
				if q != "" && !strings.Contains(strings.ToLower(c.Name), q) {
					continue
				}
				scope := make([]string, 0, len(c.Scope))
				for _, r := range c.Scope {
					scope = append(scope, r.Raw)
				}
				out = append(out, companyOut{ID: c.ID, Name: c.Name, AssetCount: c.AssetCount, Scope: scope})
			}
			return jsonResult(map[string]any{"count": len(out), "companies": out})
		},
	)
}

// splitLines splits a multi-line string into non-empty trimmed lines.
func splitLines(s string) []string {
	var out []string
	for _, line := range strings.Split(s, "\n") {
		line = strings.TrimSpace(line)
		if line != "" {
			out = append(out, line)
		}
	}
	return out
}

// WorkerTools returns the tool set for a work agent.
func (t *ToolSet) WorkerTools() []actool.CoreTool {
	return []actool.CoreTool{
		// list_findings kept: before reporting a vulnerability, query this task's confirmed vulnerabilities to avoid re-reporting the same one.
		t.listFindings(),
		t.addFinding(), t.recordFact(),
		// asset management (handlers guard nil store internally).
		// add_company_scope is not given to the worker: defining a company's asset scope is the job of planning/main/Auto; the worker only executes exploration.
		t.insertAssets(), t.listAssets(),
		// cross-work review: the worker can also reuse other works' observations to avoid duplicate effort.
		// search_all_worker_traces: no need to know the intent_id first; fetch matching steps globally by keyword;
		// get_worker_trace: once a work is pinned, list its steps/search in place/fetch the full content.
		t.searchAllWorkerTraces(), t.getWorkerTrace(),
		// node_detail: once the worker has an intent_id/node id it can query that node's full detail (together with the review above).
		t.nodeDetail(),
		// the tools below are still [not given] to the worker, kept for planner/main only (reading context and cross-work review are planning jobs,
		// the worker only executes and writes back a single intent): list_facts / list_companies / list_worker_traces.
	}
}

// MainAgentTools returns the human-interface tool set.
func (t *ToolSet) MainAgentTools() []actool.CoreTool {
	return []actool.CoreTool{
		t.graphOverview(), t.listFindings(), t.listFacts(), t.nodeDetail(),
		t.expandDigest(), // cold-digest §6.1
		t.getWorkerOutput(), t.getWorkerTrace(), t.searchAllWorkerTraces(), t.addHint(), t.addIntent(),
		// steer_work: a person can inject a real-time correction into a running intent (work) (without interrupting or losing progress).
		t.steerWorkTool(),
		// set_goals: a person can add a new final goal to this task at runtime (the planner re-judges whether it is met accordingly).
		t.setGoals(),
		// set_constraints: a person can add/change operational constraints (allow/deny) for this task at runtime, bounding the planner/worker exploration.
		t.setConstraints(),
		// asset management (handlers guard nil store internally)
		t.insertAssets(), t.addCompanyScope(), t.listAssets(),
		t.addFinding(), t.recordFact(),
		t.addTaskScope(),
		// list_untested_assets: query untested assets within this task's scope on demand (type + paging) and decide whether to test more.
		t.listUntestedAssets(),
	}
}

// AllDomainTools returns the union of all domain tools across all agent types,
// deduped by name (mainagent order wins). Used by the server to build a registry
// for injecting domain tools into agents (Auto, custom) that don't own a per-task
// ToolSet. The caller provides real stores; tools are callable at taskID=0 scope.
func (t *ToolSet) AllDomainTools() []actool.CoreTool {
	seen := map[string]bool{}
	var out []actool.CoreTool
	all := append(append(t.MainAgentTools(), t.PlannerTools()...), t.WorkerTools()...)
	for _, tool := range all {
		if !seen[tool.Name()] {
			seen[tool.Name()] = true
			out = append(out, tool)
		}
	}
	return out
}
