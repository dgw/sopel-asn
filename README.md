# sopel-asn

ASN (and MAC address) lookup plugin for Sopel IRC bots

## Installing

Releases are hosted on PyPI, so after installing Sopel, all you need is `pip`:

```shell
$ pip install sopel-asn
```

## Using

Origin lookup — Find what ASN an IP belongs to:

```
<dgw> .asn 208.67.222.222
<Sopel> [ASN] 208.67.222.0/24 | AS36692 | Cisco OpenDNS, LLC | US | ARIN |
        0001-01-01 | more info: https://bgp.tools/as/36692

<dgw> .asn 2001:4860:b002::68
<Sopel> [ASN] 2001:4860::/32 | AS15169 | Google LLC | US | ARIN | 2005-03-14 |
        more info: https://bgp.tools/as/15169
```

AS info — Find the name of an ASN's registrant:

```
<dgw> .asn 15169
<Sopel> [ASN] AS15169 | Google LLC | US | ARIN | 2000-03-30 | more info:
        https://bgp.tools/as/15169
```

MAC address info — Find the vendor name assigned to a MAC address:

```
<dgw> .mac 00-1a-2b-3c-4d-5e
<Sopel> [ASN] MAC 00:1A:2B:3C:4D:5E is registered to Ayecom Technology Co., Ltd..
```

## Background

This plugin performs network lookups via [bgp.tools](https://bgp.tools/) using
the whois protocol, as documented at https://bgp.tools/kb/api. All data provided
is best-effort; allocation dates are particularly flaky (often `0001-01-01`).
