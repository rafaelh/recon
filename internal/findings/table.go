package findings

import (
	"fmt"
	"strings"
)

// Categories of findings.
const (
	Takeover            = "takeover"
	Storage             = "storage"
	StorageUnattributed = "storage-unattributed"
	SensitivePaths      = "sensitive-paths"
	Email               = "email"
	Ports               = "ports"
	Certificates        = "certificates"
)

// Severities.
const (
	High   = "high"
	Medium = "medium"
	Low    = "low"
)

// Row is one finding type with its documented default severity.
type Row struct {
	Category, Type, Severity, Meaning string
}

// table is the one severity table. Severities are fixed in code, documented in
// --help and the README, and not configurable. Unattributed storage is low by
// construction, so it never reaches the summary's high and medium list.
var table = []Row{
	{Takeover, "dns-nxdomain", High, "a CNAME dangles (NXDOMAIN) into a provider whose names anyone can claim"},
	{Takeover, "http-fingerprint", High, "a provider-hosted name serves the page an unclaimed resource serves"},
	{Takeover, "storage-missing", High, "a bucket or account the in-scope CNAME or a page asset names does not exist"},
	{Takeover, "storage-missing-link", Low, "a missing bucket that is only the target of a plain link"},
	{Storage, "listable", High, "an attributed bucket whose contents anyone can list"},
	{Storage, "public", Medium, "an attributed bucket with an object anyone can fetch, not listable"},
	{Storage, "exists", Low, "an attributed bucket that exists and is private"},
	{StorageUnattributed, "listable", Low, "a guessed bucket nothing in scope references, listable"},
	{StorageUnattributed, "public", Low, "a guessed bucket nothing in scope references, with a public object"},
	{SensitivePaths, "<path>", Medium, "a sensitive path answered with its expected signature; the entry's severity, default medium"},
	{Email, "spf-all-plus", High, "SPF ends in +all (or a bare all): anyone may send as the domain"},
	{Email, "spf-missing", Medium, "no SPF record"},
	{Email, "spf-all-neutral", Medium, "SPF ends in ?all"},
	{Email, "spf-invalid", Medium, "several SPF records, or an include that cannot be resolved"},
	{Email, "spf-lookups", Low, "SPF needs more than 10 DNS lookups"},
	{Email, "dmarc-missing", Medium, "no DMARC record"},
	{Email, "dmarc-none", Low, "DMARC policy is none"},
	{Email, "no-mx-spf", Low, "no MX (or a null MX) and no v=spf1 -all record"},
	{Ports, "risky-port", Medium, "a port on the risky list (RDP, SMB, Telnet, databases, ...) is open"},
	{Certificates, "expired", Medium, "the certificate has expired"},
	{Certificates, "expiring", Low, "the certificate expires within --cert-expiry-days"},
	{Certificates, "self-signed", Low, "the certificate is self-signed"},
}

// SeverityTable is the documented default severity of every finding type.
func SeverityTable() []Row { return append([]Row(nil), table...) }

var rank = map[string]int{Low: 1, Medium: 2, High: 3}

func maxSeverity(a, b string) string {
	if rank[b] > rank[a] {
		return b
	}
	return a
}

// Severity is the default severity of a type in a category. A type that lists
// several kinds ("expired;self-signed") has the highest of them. A sensitive-path
// type is the path, whose default is medium (the entry's own severity applies
// to a hit). It is "" for an unknown type.
func Severity(category, typ string) string {
	if category == SensitivePaths {
		return Medium
	}
	sev := ""
	for t := range strings.SplitSeq(typ, ";") {
		found := false
		for _, r := range table {
			if r.Category == category && r.Type == t {
				sev, found = maxSeverity(sev, r.Severity), true
			}
		}
		if !found {
			return ""
		}
	}
	return sev
}

// HelpTable is the severity table as it appears in --help.
func HelpTable() string {
	var b strings.Builder
	for _, r := range table {
		fmt.Fprintf(&b, "  %-21s %-21s %-7s %s\n", r.Category, r.Type, r.Severity, r.Meaning)
	}
	return b.String()
}
