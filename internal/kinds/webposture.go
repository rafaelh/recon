package kinds

// WebPosture is the web-configuration evidence of one web service: what its
// responses say about HSTS, cookie flags, directory listings and version
// banners. The probe stores it with the web_service record of the same key, in
// the same check, and the findings package derives the low web-posture
// findings from it. It is a kind of its own so that the posture columns stay
// out of WebServiceAttrs.
var WebPosture = define[WebPostureAttrs](Kind{Name: "web_posture", HostAttr: "host"})

// WebPostureAttrs: Host is the service's host. HSTS is unset for a service
// answering over HTTP, where the header means nothing. The cookie fields hold
// cookie names only, never values, ";"-joined and sorted: those missing Secure
// (judged only over HTTPS) and those missing HttpOnly. VersionDisclosure is
// the Server and X-Powered-By values that carry a version, ";"-joined.
type WebPostureAttrs struct {
	Host              string `json:"host"`
	HSTS              *bool  `json:"hsts,omitempty"`
	CookiesNoSecure   string `json:"cookies_no_secure,omitempty"`
	CookiesNoHTTPOnly string `json:"cookies_no_httponly,omitempty"`
	DirectoryListing  bool   `json:"directory_listing"`
	VersionDisclosure string `json:"version_disclosure,omitempty"`
}
