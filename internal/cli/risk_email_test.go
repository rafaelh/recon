package cli_test

import (
	"fmt"
	"slices"
	"strings"
	"testing"

	mdns "github.com/miekg/dns"

	"github.com/rafaelh/recon/internal/egress/egresstest"
)

// mail describes the DNS of a root's email: the defaults are a healthy domain.
type mail struct {
	mx    []string // "10 mail.example.com", "0 ." for a null MX
	spf   []string
	dmarc []string
	extra func(d *egresstest.DNS)
}

func healthy() mail {
	return mail{mx: []string{"10 mail.example.com"}, spf: []string{"v=spf1 ip4:203.0.113.0/24 -all"}, dmarc: []string{"v=DMARC1; p=reject"}}
}

func (m mail) apply(d *egresstest.DNS, root string) {
	for _, x := range m.mx {
		var pref int
		var host string
		_, _ = fmt.Sscanf(x, "%d %s", &pref, &host)
		d.MX(root, pref, host)
	}
	for _, s := range m.spf {
		d.TXT(root, s)
	}
	for _, s := range m.dmarc {
		d.TXT("_dmarc."+root, s)
	}
	if m.extra != nil {
		m.extra(d)
	}
}

func includes(n int) string {
	var parts []string
	for i := 1; i <= n; i++ {
		parts = append(parts, fmt.Sprintf("include:i%d.t.test", i))
	}
	return "v=spf1 " + strings.Join(parts, " ") + " -all"
}

// B6: SPF, DMARC and MX cases, each producing exactly the findings the spec lists.
func TestRiskB6_EmailPosture(t *testing.T) {
	cases := []struct {
		name string
		edit func(*mail)
		want []string
		cols map[string]string // email-posture.csv columns
	}{
		{"healthy", func(m *mail) {}, nil, map[string]string{"mx": "mail.example.com", "spf_lookups": "0", "dmarc_policy": "reject"}},
		{"+all", func(m *mail) { m.spf = []string{"v=spf1 +all"} }, []string{"spf-all-plus"}, nil},
		{"all without qualifier", func(m *mail) { m.spf = []string{"v=spf1 mx all"} }, []string{"spf-all-plus"}, nil},
		{"?all", func(m *mail) { m.spf = []string{"v=spf1 ip4:203.0.113.1 ?all"} }, []string{"spf-all-neutral"}, nil},
		{"spf missing", func(m *mail) { m.spf = nil }, []string{"spf-missing"}, nil},
		{"several spf records", func(m *mail) { m.spf = []string{"v=spf1 -all", "v=spf1 ~all"} }, []string{"spf-invalid"}, nil},
		{"an unrelated txt is not spf", func(m *mail) { m.spf = []string{"google-site-verification=abc"} }, []string{"spf-missing"}, nil},
		{"ten lookups", func(m *mail) {
			m.spf = []string{includes(10)}
			m.extra = func(d *egresstest.DNS) {
				for i := 1; i <= 10; i++ {
					d.TXT(fmt.Sprintf("i%d.t.test", i), "v=spf1 ip4:192.0.2.1 -all")
				}
			}
		}, nil, map[string]string{"spf_lookups": "10"}},
		{"include chain over 10", func(m *mail) {
			m.spf = []string{includes(11)}
			m.extra = func(d *egresstest.DNS) {
				for i := 1; i <= 11; i++ {
					d.TXT(fmt.Sprintf("i%d.t.test", i), "v=spf1 ip4:192.0.2.1 -all")
				}
			}
		}, []string{"spf-lookups"}, map[string]string{"spf_lookups": "11"}},
		{"nested lookups count: a, mx, ptr, exists and redirect", func(m *mail) {
			m.spf = []string{"v=spf1 a mx ptr exists:x.t.test include:i1.t.test redirect=r.t.test"}
			m.extra = func(d *egresstest.DNS) {
				d.TXT("i1.t.test", "v=spf1 a a a a a -all")
				d.TXT("r.t.test", "v=spf1 mx mx -all")
			}
		}, []string{"spf-lookups"}, map[string]string{"spf_lookups": "13"}},
		{"include loop", func(m *mail) {
			m.spf = []string{"v=spf1 include:a.t.test -all"}
			m.extra = func(d *egresstest.DNS) {
				d.TXT("a.t.test", "v=spf1 include:b.t.test -all")
				d.TXT("b.t.test", "v=spf1 include:a.t.test -all")
			}
		}, []string{"spf-invalid"}, nil},
		{"include that does not exist", func(m *mail) { m.spf = []string{"v=spf1 include:gone.t.test -all"} }, []string{"spf-invalid"}, nil},
		{"+all is reported even when an include makes the SPF invalid", func(m *mail) {
			m.spf = []string{"v=spf1 include:gone.t.test +all"}
		}, []string{"spf-all-plus", "spf-invalid"}, nil},
		{"a redirect is not counted when the record has an all", func(m *mail) {
			m.spf = []string{strings.Replace(includes(10), " -all", " ~all redirect=r.t.test", 1)}
			m.extra = func(d *egresstest.DNS) {
				for i := 1; i <= 10; i++ {
					d.TXT(fmt.Sprintf("i%d.t.test", i), "v=spf1 ip4:192.0.2.1 -all")
				}
				d.TXT("r.t.test", "v=spf1 a -all")
			}
		}, nil, map[string]string{"spf_lookups": "10"}},
		{"a macro include is counted, not followed", func(m *mail) {
			m.spf = []string{"v=spf1 include:%{i}._spf.t.test -all"}
		}, nil, map[string]string{"spf_lookups": "1"}},
		{"null MX with -all", func(m *mail) { m.mx = []string{"0 ."}; m.spf = []string{"v=spf1 -all"} }, nil, map[string]string{"mx": ""}},
		{"no MX lacking -all", func(m *mail) { m.mx = nil; m.spf = []string{"v=spf1 ip4:203.0.113.1 ~all"} }, []string{"no-mx-spf"}, nil},
		{"null MX lacking -all", func(m *mail) { m.mx = []string{"0 ."}; m.spf = []string{"v=spf1 ~all"} }, []string{"no-mx-spf"}, nil},
		{"dmarc missing", func(m *mail) { m.dmarc = nil }, []string{"dmarc-missing"}, nil},
		{"p=none", func(m *mail) { m.dmarc = []string{"v=DMARC1; p=none; rua=mailto:a@example.com"} }, []string{"dmarc-none"}, map[string]string{"dmarc_policy": "none"}},
		{"p=quarantine is fine", func(m *mail) { m.dmarc = []string{"v=DMARC1; p=quarantine"} }, nil, map[string]string{"dmarc_policy": "quarantine"}},
		{"dkim selector found", func(m *mail) {
			m.extra = func(d *egresstest.DNS) { d.TXT("selector1._domainkey.example.com", "v=DKIM1; k=rsa; p=MIGf") }
		}, nil, map[string]string{"dkim_selectors": "selector1"}},
		{"no dkim selector is informational", func(m *mail) {}, nil, map[string]string{"dkim_selectors": ""}},
		{"a revoked dkim key and a non-dkim record are not selectors", func(m *mail) {
			m.extra = func(d *egresstest.DNS) {
				d.TXT("selector1._domainkey.example.com", "v=DKIM1; k=rsa; p=")
				d.TXT("k1._domainkey.example.com", "v=DMARC1; p=none")
				d.TXT("s1._domainkey.example.com", "k=rsa; p=MIGf")
			}
		}, nil, map[string]string{"dkim_selectors": "s1"}},
		{"dkim selector SERVFAIL does not fail the check", func(m *mail) {
			m.extra = func(d *egresstest.DNS) {
				d.Rcode("google._domainkey.example.com", mdns.RcodeServerFailure)
				d.TXT("k1._domainkey.example.com", "v=DKIM1; p=XYZ")
			}
		}, nil, map[string]string{"dkim_selectors": "k1"}},
	}
	for _, c := range cases {
		t.Run(c.name, func(t *testing.T) {
			x := newRisk(t, "email")
			x.names()
			m := healthy()
			c.edit(&m)
			m.apply(x.dns, "example.com")
			x.mustRun()
			got := col(current(x.rows("risk-email.csv")), "type")
			if !slices.Equal(got, c.want) {
				t.Errorf("risk-email.csv types = %v, want %v\n%s", got, c.want, x.file(eng, "risk-email.csv"))
			}
			posture := x.rows("email-posture.csv")
			if len(posture) != 1 || posture[0]["root"] != "example.com" {
				t.Fatalf("email-posture.csv = %v", posture)
			}
			for k, v := range c.cols {
				if posture[0][k] != v {
					t.Errorf("email-posture.csv %s = %q, want %q", k, posture[0][k], v)
				}
			}
			for _, r := range current(x.rows("risk-email.csv")) {
				if r["root"] != "example.com" || r["severity"] == "" {
					t.Errorf("row = %v", r)
				}
			}
		})
	}
}

// B6/D2: severities of the email findings.
func TestRiskB6_EmailSeverities(t *testing.T) {
	x := newRisk(t, "email")
	x.names()
	m := healthy()
	m.spf = []string{"v=spf1 +all"}
	m.dmarc = nil
	m.apply(x.dns, "example.com")
	x.mustRun()
	got := map[string]string{}
	for _, r := range current(x.rows("risk-email.csv")) {
		got[r["type"]] = r["severity"]
	}
	if got["spf-all-plus"] != "high" || got["dmarc-missing"] != "medium" || len(got) != 2 {
		t.Errorf("severities = %v", got)
	}
	if s := x.summaryTargets(); len(s) != 2 {
		t.Errorf("summary = %v", s)
	}
}

// B6: a SERVFAIL on _dmarc is a failed check, retried on the next run.
func TestRiskB6_DMARCServfailIsTransient(t *testing.T) {
	x := newRisk(t, "email")
	x.names()
	m := healthy()
	m.dmarc = []string{"v=DMARC1; p=none"}
	m.apply(x.dns, "example.com")
	x.dns.Rcode("_dmarc.example.com", mdns.RcodeServerFailure)
	x.mustRun()
	if st := x.state("email"); st.str("state") != "failed" || st.num("failed") != 1 {
		t.Errorf("state = %v", st)
	}
	if len(x.rows("email-posture.csv")) != 0 || len(x.completedKeys("email")) != 0 {
		t.Errorf("a failed check recorded a result: %v", x.completedKeys("email"))
	}
	x.dns.ClearRcode("_dmarc.example.com")
	x.mustRun()
	if got := col(current(x.rows("risk-email.csv")), "type"); !slices.Equal(got, []string{"dmarc-none"}) {
		t.Errorf("after the retry: %v", got)
	}
	if got := x.completedKeys("email"); len(got) != 1 || !strings.HasPrefix(got[0], "example.com|dkim=") {
		t.Errorf("check keys = %v", got)
	}
}

// B6: a SERVFAIL on an SPF include is a temperror: the check fails and is
// retried, instead of completing with a permanent spf-invalid.
func TestRiskB6_IncludeServfailIsTransient(t *testing.T) {
	x := newRisk(t, "email")
	x.names()
	m := healthy()
	m.spf = []string{"v=spf1 include:broken.t.test -all"}
	m.apply(x.dns, "example.com")
	x.dns.Rcode("broken.t.test", mdns.RcodeServerFailure)
	x.mustRun()
	if st := x.state("email"); st.str("state") != "failed" || st.num("failed") != 1 {
		t.Errorf("state = %v", st)
	}
	if len(x.rows("risk-email.csv")) != 0 || len(x.completedKeys("email")) != 0 {
		t.Errorf("a failed check recorded a result: %v", x.rows("risk-email.csv"))
	}
	x.dns.ClearRcode("broken.t.test")
	x.dns.TXT("broken.t.test", "v=spf1 ip4:192.0.2.1 -all")
	x.mustRun()
	if got := col(current(x.rows("risk-email.csv")), "type"); len(got) != 0 {
		t.Errorf("after the retry: %v", got)
	}
	if got := x.completedKeys("email"); len(got) != 1 {
		t.Errorf("check keys = %v", got)
	}
}

// B6: a SERVFAIL on a selector is recorded, not fatal.
func TestRiskB6_SelectorErrorsRecorded(t *testing.T) {
	x := newRisk(t, "email")
	x.names()
	m := healthy()
	m.apply(x.dns, "example.com")
	x.dns.Rcode("google._domainkey.example.com", mdns.RcodeServerFailure)
	x.mustRun()
	if st := x.state("email"); st.str("state") != "done" || st.num("failed") != 0 {
		t.Errorf("state = %v", st)
	}
	if a := x.obsAttrs(eng, "email_posture")["example.com"]; !strings.Contains(a, `"dkim_errors":"google"`) {
		t.Errorf("attrs = %s", a)
	}
}

// B6: for a subdomain root the organisational domain's sp= applies, and its p= when there is no sp=.
func TestRiskB6_SubdomainRootUsesOrgPolicy(t *testing.T) {
	for name, tc := range map[string]struct {
		dmarc string
		want  []string
	}{
		"sp=none":         {"v=DMARC1; p=reject; sp=none", []string{"dmarc-none"}},
		"sp wins":         {"v=DMARC1; p=none; sp=reject", nil},
		"p without sp":    {"v=DMARC1; p=none", []string{"dmarc-none"}},
		"strict p and sp": {"v=DMARC1; p=reject; sp=quarantine", nil},
	} {
		t.Run(name, func(t *testing.T) {
			x := newRisk(t, "email")
			x.names()
			x.host("sub.example.com", "203.0.113.77")
			x.dns.MX("sub.example.com", 10, "mail.example.com")
			x.dns.TXT("sub.example.com", "v=spf1 -all")
			x.dns.TXT("_dmarc.example.com", tc.dmarc)
			x.fill()
			if code := x.world.run("--authorised", "--no-permutations", "-e", "subtest", "sub.example.com"); code != 0 {
				t.Fatalf("exit %d", code)
			}
			got := col(current(x.table("subtest", "risk-email.csv")), "type")
			if !slices.Equal(got, tc.want) {
				t.Errorf("types = %v, want %v", got, tc.want)
			}
			p := x.table("subtest", "email-posture.csv")
			if len(p) != 1 || p[0]["root"] != "sub.example.com" || p[0]["dmarc"] != tc.dmarc {
				t.Errorf("email-posture.csv = %v", p)
			}
			if x.dns.Count("_dmarc.sub.example.com", "TXT") != 1 || x.dns.Count("_dmarc.example.com", "TXT") != 1 {
				t.Errorf("DMARC lookups: sub %d, org %d", x.dns.Count("_dmarc.sub.example.com", "TXT"), x.dns.Count("_dmarc.example.com", "TXT"))
			}
		})
	}
}

// B6: only in-scope input roots are checked; an excluded root is not.
func TestRiskB6_OnlyInScopeRoots(t *testing.T) {
	x := newRisk(t, "email")
	x.names()
	healthy().apply(x.dns, "example.com")
	x.mustRun("--cidr", "198.51.100.0/24")
	if got := x.completedKeys("email"); len(got) != 1 {
		t.Errorf("checks = %v", got)
	}
	x.mustRun("-x", "example.com")
	if got := current(x.rows("email-posture.csv")); len(got) != 0 {
		t.Errorf("an excluded root is still reported: %v", got)
	}
}
