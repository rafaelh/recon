package kinds

// The record kinds. Each is a handle (Of or Bare) with its showing rules and,
// for an Of, the struct of attributes its observations carry.
//
// A field the writer always sets has no omitempty, so a zero is stored (and
// rendered: an spf_lookups of 0 is "0"). A field set only sometimes has
// omitempty, and is a pointer when its zero differs from its absence (a
// tls_self_signed of false is "false", no TLS at all is ""). Several stages
// may observe one record; the store merges their attributes field by field,
// so a stage that does not know a field leaves it out.

// Entities, classified against the scope.
var (
	Hostname = define[HostnameAttrs](Kind{Name: "hostname", Singular: "host", Category: Hosts, Entity: true, Printed: true})
	Root     = defineBare(Kind{Name: "root", Singular: "root", Category: Candidates, Entity: true})
	Netblock = define[NetblockAttrs](Kind{Name: "netblock", Singular: "netblock", Category: Netblocks, Entity: true})
	// ExcludedKind is an address or name that triggered an exclusion at dial
	// time; Excluded is its summary category.
	ExcludedKind = define[ExcludedAttrs](Kind{Name: "excluded", Singular: "excluded", Category: Excluded, Entity: true})
)

// HostnameAttrs: the Common Crawl index a name was found in, if it came from one.
type HostnameAttrs struct {
	Index string `json:"index,omitempty"`
}

// NetblockAttrs: the ASN that announces it ("AS123" or "123", as the input
// gave it) and, from an organisation pivot, the organisation.
type NetblockAttrs struct {
	ASN string `json:"asn,omitempty"`
	Org string `json:"org,omitempty"`
}

// ExcludedAttrs: why it was excluded.
type ExcludedAttrs struct {
	Reason string `json:"reason"`
}

// DNS and address inventory.
var (
	Resolution    = define[ResolutionAttrs](Kind{Name: "resolution"})
	IP            = defineBare(Kind{Name: "ip", Singular: "ip", Category: "ips", Counted: true})
	Unresolved    = define[UnresolvedAttrs](Kind{Name: "unresolved", Singular: "unresolved name", Category: "unresolved names", Counted: true})
	Wildcard      = define[WildcardAttrs](Kind{Name: "wildcard"})
	IPOwner       = define[IPOwnerAttrs](Kind{Name: "ip_owner"})
	IPHostname    = define[IPHostnameAttrs](Kind{Name: "ip_hostname"})
	ProviderRange = define[ProviderRangeAttrs](Kind{Name: "provider_range"})
)

// ResolutionAttrs is one DNS answer: a name's A, AAAA or CNAME value, or a
// root's NS, SOA, TXT or CAA value. Only A, AAAA and CNAME rows decide what is
// resolved, contacted or checked for wildcards.
type ResolutionAttrs struct {
	Name  string `json:"name"`
	Type  string `json:"type"`
	Value string `json:"value"`
}

// UnresolvedAttrs: why a name has no address (NXDOMAIN, SERVFAIL or NODATA).
type UnresolvedAttrs struct {
	RCode string `json:"rcode"`
}

// WildcardAttrs: what every name in a wildcard zone resolves to.
type WildcardAttrs struct {
	Addrs []string `json:"addrs"`
	CNAME string   `json:"cname"`
}

// IPOwnerAttrs: who announces an address.
type IPOwnerAttrs struct {
	ASN    int    `json:"asn"`
	Prefix string `json:"prefix"`
	Holder string `json:"holder"`
}

// IPHostnameAttrs: a name an address points back to, and where that came from.
type IPHostnameAttrs struct {
	IP       string `json:"ip"`
	Hostname string `json:"hostname"`
	Source   string `json:"source"`
}

// ProviderRangeAttrs: an address range a cloud or SaaS provider publishes.
type ProviderRangeAttrs struct {
	Provider string `json:"provider"`
	Prefix   string `json:"prefix"`
	Service  string `json:"service"`
	Region   string `json:"region"`
}

// Web.
var (
	WebService = define[WebServiceAttrs](Kind{Name: "web_service", Singular: "web service", Category: "web services", Printed: true, HostAttr: "host"})
	HTTPPort   = define[HTTPPortAttrs](Kind{Name: "http_port"})
	URL        = define[URLAttrs](Kind{Name: "url", Singular: "url", Category: "urls", Counted: true, HostAttr: "host"})
)

// WebServiceAttrs is what a probe of an origin found.
type WebServiceAttrs struct {
	URL          string `json:"url"`
	Host         string `json:"host"`
	Port         int    `json:"port"`
	Scheme       string `json:"scheme"`
	Status       int    `json:"status"`
	Server       string `json:"server"`
	Technologies string `json:"technologies"` // ";"-joined
	Redirect     string `json:"redirect,omitempty"`
	FinalURL     string `json:"final_url,omitempty"`
	Title        string `json:"title,omitempty"`
	// TLS, set only when the service presented a certificate.
	TLSSubject    string `json:"tls_subject,omitempty"`
	TLSSANs       string `json:"tls_sans,omitempty"` // ";"-joined
	TLSIssuer     string `json:"tls_issuer,omitempty"`
	TLSExpiry     string `json:"tls_expiry,omitempty"` // YYYY-MM-DD
	TLSError      string `json:"tls_error,omitempty"`
	TLSSelfSigned *bool  `json:"tls_self_signed,omitempty"`
}

// HTTPPortAttrs: a non-standard port that answered HTTP, for the probe.
type HTTPPortAttrs struct {
	Scheme string `json:"scheme"`
	Host   string `json:"host"`
}

// URLAttrs: a URL found by crawling, a redirect or a web archive. Status is
// set only once the URL has been fetched.
type URLAttrs struct {
	URL    string `json:"url"`
	Host   string `json:"host"`
	Status int    `json:"status,omitempty"`
}

// Ports.
var OpenPort = define[OpenPortAttrs](Kind{Name: "open_port", Singular: "open port", Category: "open ports", Printed: true, PortKey: true})

// OpenPortAttrs: an open TCP port and the banner it sent unprompted, escaped
// with strconv.Quote's rules and without the quotes.
type OpenPortAttrs struct {
	IP     string `json:"ip"`
	Port   int    `json:"port"`
	Banner string `json:"banner"`
}

// Findings, derived by the findings package. Their attributes depend on the
// finding's category, which the findings package owns.
var Finding = define[map[string]any](Kind{Name: "finding", Singular: "finding", Category: "findings", Printed: true})

// Evidence: stages store these, the findings package derives findings from them.
var (
	TakeoverHTTP   = define[TakeoverHTTPAttrs](Kind{Name: "takeover_http"})
	Storage        = define[StorageAttrs](Kind{Name: "storage"})
	StorageAccount = define[StorageAccountAttrs](Kind{Name: "storage_account"})
	StorageObject  = define[StorageObjectAttrs](Kind{Name: "storage_object"})
	StorageRef     = define[StorageRefAttrs](Kind{Name: "storage_ref", HostAttr: "page_host"})
	SensitiveHit   = define[SensitiveHitAttrs](Kind{Name: "sensitive_hit"})
	EmailPosture   = define[EmailPostureAttrs](Kind{Name: "email_posture", HostKey: true})
)

// TakeoverHTTPAttrs: a provider-hosted service whose root serves the page of
// an unclaimed resource.
type TakeoverHTTPAttrs struct {
	Host            string `json:"host"`
	URL             string `json:"url"`
	Status          int    `json:"status"`
	Service         string `json:"service"`
	Provider        string `json:"provider"`
	ProviderService string `json:"provider_service"`
	CNAME           string `json:"cname"`
}

// StorageAttrs: what an anonymous listing of a bucket or container said.
// Exists is unset when the answer cannot tell (Azure answers a private and a
// missing container alike), and Listable when the bucket does not exist.
type StorageAttrs struct {
	Provider    string   `json:"provider"`
	Name        string   `json:"name"`
	Container   string   `json:"container"`
	Exists      *bool    `json:"exists,omitempty"`
	Listable    *bool    `json:"listable,omitempty"`
	ObjectCount string   `json:"object_count,omitempty"` // "1000+" when the listing was cut
	FirstKeys   []string `json:"first_keys,omitempty"`
	Region      string   `json:"region,omitempty"`
}

// StorageAccountAttrs: whether an Azure storage account exists. Exists is a
// pointer so that a record without a usable value reads as unknown, never as
// a missing (claimable) account.
type StorageAccountAttrs struct {
	Exists *bool `json:"exists"`
}

// StorageObjectAttrs: whether an object of a bucket can be fetched anonymously.
type StorageObjectAttrs struct {
	Bucket    string `json:"bucket"` // the storage record key
	Provider  string `json:"provider"`
	Name      string `json:"name"`
	Container string `json:"container"`
	Object    string `json:"object"`
	Public    bool   `json:"public"`
	URL       string `json:"url"`
}

// StorageRefAttrs: a page that points at a bucket, container or object.
type StorageRefAttrs struct {
	Provider  string `json:"provider"`
	Name      string `json:"name"`
	Container string `json:"container"`
	Object    string `json:"object"`
	URL       string `json:"url"`
	Page      string `json:"page"`
	PageHost  string `json:"page_host"`
	Via       string `json:"via"` // how the page refers to it: asset, link, ...
}

// SensitiveHitAttrs: a sensitive path that answered with its expected signature.
type SensitiveHitAttrs struct {
	Service   string `json:"service"`
	Host      string `json:"host"`
	URL       string `json:"url"`
	Path      string `json:"path"`
	Status    int    `json:"status"`
	Size      Size   `json:"size"`
	Signature string `json:"signature"`
	Hash      string `json:"hash"` // of the sensitive-path entry
}

// EmailPostureAttrs: the SPF, DMARC, MX and DKIM records of a root domain.
type EmailPostureAttrs struct {
	MX            string `json:"mx"` // ";"-joined
	SPFRecords    int    `json:"spf_records"`
	SPF           string `json:"spf"`
	SPFAll        string `json:"spf_all"`
	SPFLookups    int    `json:"spf_lookups"`
	SPFError      string `json:"spf_error"`
	DMARC         string `json:"dmarc"`
	DMARCPolicy   string `json:"dmarc_policy"`
	DMARCSource   string `json:"dmarc_source"`
	DKIMSelectors string `json:"dkim_selectors"` // ";"-joined
	DKIMErrors    string `json:"dkim_errors"`    // ";"-joined
}
