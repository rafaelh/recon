Would change behaviour:

- Sharing one hostname-cleaning helper: the subdomains stage stores international domain names without converting them to punycode (their ASCII form). Fixing that changes stored keys.
- Moving the asn stage onto httpsrc.Get: its failure handling would change.
- Merging stripControl and report.Sanitize: they already strip different characters.
- Switching DefaultConfigPath to Go's home or config directory lookups: the macOS path would change.


Too big for a cleanup pass:

Prepared statements and fewer SQL statements per observation in the store.
Reusing HTTP connections, which would need rate limiting reworked.
Encoding observation attributes to JSON only once.
Making how a finding is announced a property of the finding kind, and replacing the hard-coded "asn" stage name.
