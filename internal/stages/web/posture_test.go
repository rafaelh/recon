package web

import (
	"testing"
)

type hdr = map[string][]string

// resp is a hop for a response to a request for url, with no media type.
func resp(url string, h hdr, body string) *hop { return hopAt(url, "", h, []byte(body)) }

// htmlPage is a hop for an HTML response.
func htmlPage(url, body string) *hop { return hopAt(url, "text/html", nil, []byte(body)) }

func chainOf(hops ...*hop) []*hop { return hops }

func TestPosture_HSTSIsReadFromTheFirstResponseOnly(t *testing.T) {
	const sts = "max-age=31536000"
	for name, tc := range map[string]struct {
		chain []*hop
		want  string
	}{
		"first has it": {chainOf(
			resp("https://a.example.com/", hdr{"Strict-Transport-Security": {sts}}, ""),
			htmlPage("https://a.example.com/home", "<title>x</title>"),
		), "yes"},
		"only a later response has it": {chainOf(
			resp("https://a.example.com/", hdr{}, ""),
			resp("https://a.example.com/home", hdr{"Strict-Transport-Security": {sts}}, ""),
		), "no"},
		"blank value": {chainOf(resp("https://a.example.com/", hdr{"Strict-Transport-Security": {" "}}, "")), "no"},
		"none":        {chainOf(resp("https://a.example.com/", hdr{}, "")), "no"},
		"http service has no answer": {chainOf(
			resp("http://a.example.com/", hdr{"Strict-Transport-Security": {sts}}, ""),
		), "unset"},
	} {
		t.Run(name, func(t *testing.T) {
			got := "unset"
			if a := posture("a.example.com", tc.chain); a.HSTS != nil {
				got = map[bool]string{true: "yes", false: "no"}[*a.HSTS]
			}
			if got != tc.want {
				t.Errorf("hsts = %s, want %s", got, tc.want)
			}
		})
	}
}

func TestPosture_CookieFlags(t *testing.T) {
	for name, tc := range map[string]struct {
		url                  string
		cookies              []string
		noSecure, noHTTPOnly string
	}{
		"https missing both":                  {"https://a.example.com/", []string{"sid=abc123"}, "sid", "sid"},
		"https has both":                      {"https://a.example.com/", []string{"sid=abc123; Secure; HttpOnly"}, "", ""},
		"flags are any case":                  {"https://a.example.com/", []string{"sid=1; SECURE; httponly; Path=/"}, "", ""},
		"https missing secure":                {"https://a.example.com/", []string{"sid=1; HttpOnly"}, "sid", ""},
		"https missing httponly":              {"https://a.example.com/", []string{"sid=1; Secure"}, "", "sid"},
		"http judges httponly only":           {"http://a.example.com/", []string{"sid=1; Secure"}, "", "sid"},
		"http without secure is not insecure": {"http://a.example.com/", []string{"sid=1; HttpOnly"}, "", ""},
		"a flag is not a value":               {"https://a.example.com/", []string{"sid=Secure; HttpOnly"}, "sid", ""},
		"several cookies sorted":              {"https://a.example.com/", []string{"b=1", "a=2; Secure; HttpOnly", "c=3; HttpOnly"}, "b;c", "b"},
		"attribute spacing":                   {"https://a.example.com/", []string{"sid=1 ;Secure;  HttpOnly "}, "", ""},
		"empty value still has a name":        {"https://a.example.com/", []string{"sid="}, "sid", "sid"},
		"no name is ignored":                  {"https://a.example.com/", []string{"=orphan", "garbage"}, "", ""},
	} {
		t.Run(name, func(t *testing.T) {
			a := posture("a.example.com", chainOf(resp(tc.url, hdr{"Set-Cookie": tc.cookies}, "")))
			if a.CookiesNoSecure != tc.noSecure || a.CookiesNoHTTPOnly != tc.noHTTPOnly {
				t.Errorf("no secure = %q, no httponly = %q; want %q, %q", a.CookiesNoSecure, a.CookiesNoHTTPOnly, tc.noSecure, tc.noHTTPOnly)
			}
		})
	}
}

// A cookie set by any response in the redirect chain counts, and Secure is
// judged against the scheme the response arrived over.
func TestPosture_CookiesFromEveryResponseInTheChain(t *testing.T) {
	a := posture("a.example.com", chainOf(
		resp("https://a.example.com/", hdr{"Set-Cookie": {"tracker=1; HttpOnly"}}, ""),
		resp("https://a.example.com/login", hdr{"Set-Cookie": {"csrf=1; Secure"}}, ""),
		resp("https://a.example.com/home", hdr{"Set-Cookie": {"sid=1; Secure; HttpOnly"}}, ""),
	))
	if a.CookiesNoSecure != "tracker" || a.CookiesNoHTTPOnly != "csrf" {
		t.Errorf("no secure = %q, no httponly = %q", a.CookiesNoSecure, a.CookiesNoHTTPOnly)
	}

	// A cookie set over HTTP by an http-to-https redirect lacks HttpOnly, but
	// Secure is not judged for a response that arrived over HTTP.
	a = posture("a.example.com", chainOf(
		resp("http://a.example.com/", hdr{"Set-Cookie": {"pre=1"}}, ""),
		resp("https://a.example.com/", hdr{"Set-Cookie": {"post=1"}}, ""),
	))
	if a.CookiesNoSecure != "post" || a.CookiesNoHTTPOnly != "post;pre" {
		t.Errorf("no secure = %q, no httponly = %q", a.CookiesNoSecure, a.CookiesNoHTTPOnly)
	}
}

// Only the sanitised name is kept; exact equality rules out any value or control character.
func TestPosture_CookieNamesAreSanitisedAndValuesNeverKept(t *testing.T) {
	a := posture("a.example.com", chainOf(resp("https://a.example.com/", hdr{"Set-Cookie": {
		"s\x1b[31mid\x07=TOPSECRETVALUE; Path=/",
		"tok=ANOTHERSECRET; Secure; HttpOnly",
	}}, "")))
	if a.CookiesNoSecure != "sid" || a.CookiesNoHTTPOnly != "sid" {
		t.Errorf("cookie names = %q, %q; want the sanitised name sid", a.CookiesNoSecure, a.CookiesNoHTTPOnly)
	}
}

func TestPosture_HostIsTheServices(t *testing.T) {
	if h := posture("a.example.com", chainOf(resp("http://a.example.com/", hdr{}, ""))).Host; h != "a.example.com" {
		t.Errorf("Host = %q", h)
	}
}

func TestPosture_DirectoryListing(t *testing.T) {
	for name, tc := range map[string]struct {
		body string
		want bool
	}{
		"title":             {`<html><head><title>Index of /</title></head><body></body></html>`, true},
		"title with a path": {`<title>Index of /backups</title>`, true},
		"first heading":     {`<html><head><title>Files</title></head><body><h1>Index of /pub</h1><pre></pre></body></html>`, true},
		"whitespace":        {"<title>\n  Index   of /\n</title>", true},
		"not at the start":  {`<title>The Index of /things</title>`, false},
		"later heading":     {`<title>Home</title><body><h1>Welcome</h1><h2>Index of /</h2></body>`, false},
		"index of a word":   {`<title>Index of Services</title>`, false},
		"ordinary page":     {`<title>Welcome</title><h1>Hello</h1>`, false},
		"no page":           {``, false},
	} {
		t.Run(name, func(t *testing.T) {
			if got := posture("a.example.com", chainOf(htmlPage("https://a.example.com/", tc.body))).DirectoryListing; got != tc.want {
				t.Errorf("directory listing = %v, want %v", got, tc.want)
			}
		})
	}
	// A listing served as something other than HTML is not read as one.
	plain := hopAt("https://a.example.com/", "text/plain", nil, []byte("<title>Index of /</title>"))
	if posture("a.example.com", chainOf(plain)).DirectoryListing {
		t.Error("a text/plain body was read as a directory listing")
	}
}

// The page that counts is the last one of the chain served by the service's
// own origin; a listing on another origin it redirects to is not this service's.
func TestPosture_DirectoryListingFromTheLastSameOriginPage(t *testing.T) {
	const listing = `<title>Index of /</title>`
	for name, chain := range map[string][]*hop{
		"listing at the end": chainOf(
			htmlPage("https://a.example.com/", "<title>Moved</title>"),
			htmlPage("https://a.example.com/files/", listing),
		),
		"listing on the first page only": chainOf(htmlPage("https://a.example.com/", listing)),
	} {
		if !posture("a.example.com", chain).DirectoryListing {
			t.Errorf("%s: want a directory listing", name)
		}
	}
	for name, chain := range map[string][]*hop{
		"listing on another host": chainOf(
			htmlPage("https://a.example.com/", "<title>Moved</title>"),
			htmlPage("https://b.example.com/", listing),
		),
		"another scheme": chainOf(
			htmlPage("http://a.example.com/", "<title>Moved</title>"),
			htmlPage("https://a.example.com/", listing),
		),
		"another port": chainOf(
			htmlPage("https://a.example.com/", "<title>Moved</title>"),
			htmlPage("https://a.example.com:8443/", listing),
		),
		"the same-origin page is ordinary": chainOf(
			htmlPage("https://a.example.com/", "<title>Home</title>"),
			htmlPage("https://b.example.com/", listing),
		),
		// The last same-origin page decides, not an earlier listing.
		"an earlier page of the chain": chainOf(
			htmlPage("https://a.example.com/", listing),
			htmlPage("https://a.example.com/home", "<title>Home</title>"),
		),
	} {
		if posture("a.example.com", chain).DirectoryListing {
			t.Errorf("%s: a listing that is not the service's last own page was reported", name)
		}
	}
}

func TestPosture_VersionDisclosure(t *testing.T) {
	for name, tc := range map[string]struct {
		header hdr
		want   string
	}{
		"apache":                {hdr{"Server": {"Apache/2.4.41 (Ubuntu)"}}, "Apache/2.4.41 (Ubuntu)"},
		"plain apache":          {hdr{"Server": {"Apache/2.4.41"}}, "Apache/2.4.41"},
		"nginx without version": {hdr{"Server": {"nginx"}}, ""},
		"asp.net":               {hdr{"X-Powered-By": {"ASP.NET"}}, ""},
		"slash then letter":     {hdr{"Server": {"Microsoft-IIS/Ten"}}, ""},
		"digit without slash":   {hdr{"Server": {"nginx 1.25"}}, ""},
		"both headers":          {hdr{"Server": {"nginx/1.25.3"}, "X-Powered-By": {"PHP/8.2.1"}}, "nginx/1.25.3;PHP/8.2.1"},
		"only the versioned":    {hdr{"Server": {"nginx"}, "X-Powered-By": {"PHP/8.2.1"}}, "PHP/8.2.1"},
		"several values":        {hdr{"X-Powered-By": {"PHP/8.2.1", "Express"}}, "PHP/8.2.1"},
		"control characters":    {hdr{"Server": {"Apache/2.4\x1b[31m.41"}}, "Apache/2.4.41"},
	} {
		t.Run(name, func(t *testing.T) {
			if got := posture("a.example.com", chainOf(resp("http://a.example.com/", tc.header, ""))).VersionDisclosure; got != tc.want {
				t.Errorf("version disclosure = %q, want %q", got, tc.want)
			}
		})
	}
	// Only the first response is read.
	chain := chainOf(
		resp("http://a.example.com/", hdr{"Server": {"nginx"}}, ""),
		resp("http://a.example.com/x", hdr{"Server": {"Apache/2.4.41"}}, ""),
	)
	if got := posture("a.example.com", chain).VersionDisclosure; got != "" {
		t.Errorf("a later response's Server header was read: %q", got)
	}
}

// A page is parsed once, however many readers ask.
func TestHopParsesItsPageOnce(t *testing.T) {
	h := htmlPage("https://a.example.com/", "<title>Index of /</title>")
	p1, ok1 := h.page()
	h.body = []byte("<title>changed</title>") // a second parse would see this
	p2, ok2 := h.page()
	if !ok1 || !ok2 || p1.title() != "Index of /" || p2.title() != "Index of /" {
		t.Errorf("titles = %q, %q", p1.title(), p2.title())
	}
	if _, ok := resp("https://a.example.com/", hdr{}, "<title>x</title>").page(); ok {
		t.Error("a response with no media type has a page")
	}
}
