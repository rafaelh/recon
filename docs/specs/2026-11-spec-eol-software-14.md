# Spec 14: end-of-life software

## Goal

A web server, framework or network service whose detected version is past the end of security
support for its release cycle is reported as a finding, from versions recon already captures.

## Behaviours

1. recon embeds a table of products and the end of security support of each release cycle, as
   endoflife.date records them, for each product endoflife.date tracks that recon can version
   from Wappalyzer or from SSH, FTP and SMTP banners. The README lists the products, the data
   source and the date the data was taken. A run warns once when the embedded data is older than
   twelve months.
2. A version whose cycle's end date is on or before the run date (UTC) is a medium finding of type
   `eol` in `risk-eol-software.csv`: target (the service URL, or `ip:port` with a hostnames column
   as in `risk-ports.csv`), product, version, end date and where it was seen (`web` or `banner`).
   Each end-of-life product on a service or port is its own finding. A version carrying a
   distribution suffix (`Debian`, `Ubuntu`, `CentOS`, `+deb`, `~bpo` and the like) is one step
   lower (low) with `distribution build` in the detail. A version known only from a Shodan port
   report is one step lower and marked unconfirmed, as in Spec 4.
3. A cycle whose end date is after the run date and within `eol_warn_days` (default 90, flag
   `--eol-warn-days`, minimum 1, 0 disables) is a low finding of type `eol-approaching`.
4. A version that cannot be matched to a cycle in the table produces no finding.
5. SSH, FTP and SMTP banners in `open-ports.csv` gain `product` and `version` columns when the
   banner is recognised (OpenSSH, Dropbear, ProFTPD, vsftpd, Pure-FTPd, Postfix, Exim, Sendmail,
   Microsoft IIS/FTP and Exchange SMTP at least, listed in the README); unrecognised banners leave
   both empty. Values are sanitised like other target text. Existing engagements gain the columns
   on their next run without new contact.
6. Findings are re-derived on every run from the latest probe and banner records and the run
   date, so one may appear with no new contact when the date passes an end date or the table
   changes, and under `--passive` they come from records kept from earlier runs. A finding goes not
   current when `--redo httpprobe` or `--redo ports` no longer shows that version. Only in-scope web
   services and port-eligible addresses are assessed, as for other findings. Both types appear in
   the `--help` severity table and the file in the README output table.
