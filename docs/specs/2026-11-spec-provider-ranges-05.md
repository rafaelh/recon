# Spec 5: more published provider address ranges

## Goal

`ips.csv` names the provider and, where published, the service or region for addresses on
Cloudflare, Fastly, DigitalOcean, Oracle Cloud and Linode even when the owner lookup fails, and
DigitalOcean addresses are classified as the customer's own machines rather than wholesale as
shared hosting.

## Behaviours

1. The `providerranges` stage fetches the published range lists of Cloudflare (IPv4 and IPv6, two
   checks), Fastly, DigitalOcean, Oracle Cloud and Linode in addition to AWS and GCP. Each list is
   its own check, fetched once per engagement and refreshed only by `--redo providerranges`. On an
   existing engagement the new lists are fetched and AWS and GCP are not re-fetched.
2. A published range takes precedence over the ASN classification; a CNAME into a known provider
   still makes a host shared. Cloudflare and Fastly addresses are shared infrastructure and are
   not port-checked. DigitalOcean and Linode addresses are dedicated and port-eligible, which for
   DigitalOcean is a change from today and means the next active run may handshake addresses it
   previously skipped; the README notes this. Oracle ranges tagged as object storage or Oracle
   services are shared; the rest are dedicated. Which hosts are requested for sensitive paths is
   unchanged. An address covered by two lists shows both providers `;`-joined.
3. Azure is not fetched. The README's list of range publishers names the seven providers and says
   Azure is classified by ASN only because Microsoft publishes its ranges at a changing URL.
4. A list that fails to download, or downloads but yields no ranges, is a failed check: the
   previously fetched ranges still apply and the usual `--verbose` failed-check warning names the
   provider. Nothing is reported as a finding because of a missing list.
5. The README passive-boundary section names every range publisher contacted.
