Would change behaviour:

- Merging stripControl and report.Sanitize: they already strip different characters.
- Switching DefaultConfigPath to Go's home or config directory lookups: the macOS path would change.


Too big for a cleanup pass:

Prepared statements and fewer SQL statements per observation in the store.
Reusing HTTP connections, which would need rate limiting reworked.
Encoding observation attributes to JSON only once.
Making how a finding is announced a property of the finding kind, and replacing the hard-coded "asn" stage name.
