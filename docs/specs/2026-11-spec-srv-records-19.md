# Spec 19: service records and well-known hostnames

## Goal

Mail, identity, voice, collaboration and game infrastructure advertised through SRV records and
well-known hostnames is discovered for each in-scope root, without widening what recon connects to.

## Behaviours

1. The `dnsroot` stage (Spec 3) also queries, as its own check per root, a fixed SRV list:
   `_sip._tls`, `_sip._tcp`, `_sipfederationtls._tcp`, `_autodiscover._tcp`, `_ldap._tcp`,
   `_kerberos._tcp`, `_xmpp-server._tcp`, `_xmpp-client._tcp`, `_caldav._tcp`, `_carddav._tcp`,
   `_imaps._tcp`, `_submission._tcp`, `_matrix._tcp`, `_minecraft._tcp`. Adding SRV to an
   existing engagement runs the new check once; nothing already recorded is re-queried.
2. Each SRV answer is a row in `resolutions.csv` with type `SRV`, the service name as the name and
   `priority weight port target` as the value. SRV service names are not hostnames and are not
   tested as wildcard zones. A target of `.` records nothing. An in-scope target is recorded as a
   hostname; any other target is a row in `third-parties.csv` with mechanism `srv` and the
   target's registrable domain, not a candidate.
3. SRV ports are reported, never connected to: `ips.csv` gains an `srv_ports` column listing the
   ports SRV records advertise for the address's hostnames. The `ports` stage keeps to the
   configured port list and the README boundary text is unchanged.
4. The permutations stage always tries `autodiscover`, `lyncdiscover`, `enterpriseenrollment`,
   `enterpriseregistration` and `mta-sts` under each root, even when the wordlist lacks them,
   and only when permutations are enabled. These fixed labels are part of the permutation check
   like any wordlist change.
