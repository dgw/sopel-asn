# sopel-asn

ASN lookup plugin for Sopel IRC bots

## Installing

Releases are hosted on PyPI, so after installing Sopel, all you need is `pip`:

```shell
$ pip install sopel-asn
```

## Using

**[IPv4, IPv6]** Origin lookup — Find what ASN an IP belongs to:

```
<dgw> .asno 208.67.222.222
<Sopel> [ASN] AS36692 | 208.67.222.0/24 | US | Registered at arin on 2006-06-06

<dgw> .asnorigin 2001:4860:b002::68
<Sopel> [ASN] AS15169 | 2001:4860::/32 | US | Registered at arin on 2005-03-14
```

**[IPv4]** Peer lookup — Find other BGP peers of an IP address:

```
<dgw> .asnp 1.1.1.1
<Sopel> [ASN] 1.1.1.0/24 | AU | Registered at apnic on 2011-08-11 | Peer ASNs:
        174, 2914, 3257, 6461, 6939, 13335, 23352

# Note: BGP peer lookup is not currently supported for IPv6 addresses.
<dgw> .asnpeers 2001:4860:b002::68
<Sopel> No records found for 2001:4860:b002::68.
```

**[ASN]** AS info — Find the name of an ASN's registrant:

```
<dgw> .asn 15169
<Sopel> [ASN] AS15169 | GOOGLE, US | US | Registered at arin on 2000-03-30
```

## Background

This plugin performs network lookups using Team Cymru's DNS interface, as
documented at https://www.team-cymru.com/ip-asn-mapping

All data provided is best-effort, and not all lookup types are supported (e.g.
IPv6 BGP peers, as noted above).
