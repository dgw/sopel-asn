"""Utility functions for sopel-asn."""
from __future__ import annotations

import ipaddress
import re
import socket

from sopel.tools import get_logger


LOGGER = get_logger('asn.util')


class ASRecord:
    """An object representing an ASN record from bgp.tools."""
    def __init__(self, data: dict):
        self._data = data

    @classmethod
    def from_string(cls, data: str) -> ASRecord:
        """Create an ASRecord from a bgp.tools whois response string."""
        return cls(parse_asn_whois(data))

    @classmethod
    def from_asn(cls, asn: str) -> ASRecord:
        """Create an ASRecord by querying bgp.tools for the given ASN."""
        asn = asn.upper()  # ensure "AS" prefix is uppercase, if present
        if not asn.startswith('AS'):
            asn = 'AS' + asn
        if not asn[2:].isdigit():
            raise ValueError(f"{asn} is not a valid AS number (must be in ASxxx format).")

        response = bgp_tools_request(asn)
        return cls.from_string(response)

    @classmethod
    def from_ip(
        cls,
        ip: str | ipaddress.IPv4Address | ipaddress.IPv6Address
    ) -> ASRecord:
        """Create an ASRecord by querying bgp.tools for the given IP address."""
        if not isinstance(ip, (ipaddress.IPv4Address, ipaddress.IPv6Address)):
            try:
                ip = ipaddress.ip_address(ip)
            except ValueError:
                raise ValueError(f"{ip} is not a valid IP address.")

        response = bgp_tools_request(str(ip))
        return cls.from_string(response)

    @classmethod
    def from_free_query(cls, query: str) -> ASRecord:
        """Create an ASRecord by querying bgp.tools for the given free-form query.

        The query may be an IP address or AS number (in `ASxxx` format).
        """
        query = query.upper().strip()
        if query.startswith('AS') and query[2:].isdigit():
            return cls.from_asn(query)
        elif query.isdigit():
            return cls.from_asn('AS' + query)
        else:
            return cls.from_ip(query)

    @property
    def asn(self) -> str:
        """The AS number."""
        return self._data.get('as')

    @property
    def name(self) -> str:
        """The AS name."""
        return self._data.get('as_name')

    @property
    def prefix(self) -> str:
        """The BGP prefix."""
        return self._data.get('bgp_prefix')

    @property
    def country(self) -> str:
        """The country code."""
        return self._data.get('cc')

    @property
    def registry(self) -> str:
        """The allocating registry."""
        return self._data.get('registry')

    @property
    def allocation_date(self) -> str:
        """The allocation date."""
        return self._data.get('allocated')

    def __repr__(self) -> str:
        return f"<{self._data.get('as name', 'Unknown AS')} ({self.asn})>"

    def __str__(self) -> str:
        """Format the ASRecord for display."""
        prefix = f"{self.prefix} | " if self.prefix else ''
        return (
            f"{prefix}AS{self.asn} | {self.name} | {self.country} | "
            f"{self.registry} | {self.allocation_date}"
        )


class MACRecord:
    """An object representing a MAC address record from bgp.tools."""
    def __init__(self, mac: str, data: dict):
        self._data = data
        self._mac = mac.upper().replace('-', ':')

    @classmethod
    def from_string(cls, data: str, mac: str = "::") -> MACRecord:
        """Create a MACRecord from a bgp.tools whois response string.

        The `mac` parameter is optional, but recommended, as without it the
        `vendor` has no context.
        """
        return cls(mac, parse_mac_whois(data))

    @classmethod
    def from_mac(cls, mac: str) -> MACRecord:
        """Create a MACRecord by querying bgp.tools for the given MAC address."""
        mac = mac.upper().replace('-', ':')
        if not re.match(r'^[0-9A-F]{2}(:[0-9A-F]{2}){5}$', mac):
            raise ValueError(f"{mac} is not a valid MAC address (must be in XX:XX:XX:XX:XX:XX format).")

        response = bgp_tools_request(mac)
        return cls.from_string(response, mac)

    @property
    def mac(self) -> str:
        """The MAC address."""
        return self._mac

    @property
    def vendor(self) -> str:
        """The vendor name."""
        return self._data.get('vendor')

    def __repr__(self) -> str:
        return f"<{self.mac} ({self.vendor})>"

    def __str__(self) -> str:
        """Format the MACRecord for display."""
        return f"{self.mac} | {self.vendor}"


# `bgp_tools_request()` is a modified version of `whois_request()` from python-whois (WTFPL)
# https://github.com/joepie91/python-whois/blob/7b0ddf755b3d706860d5d8cb80c598fd854a48ca/pythonwhois/net.py#L84-L94
def bgp_tools_request(query: str) -> str:
    """Make a request to bgp.tools' whois service."""
    sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    sock.connect(("bgp.tools", 43))
    sock.send(("%s\r\n" % query).encode("utf-8"))
    buff = b""
    while True:
        data = sock.recv(1024)
        if len(data) == 0:
            break
        buff += data
    return buff.decode("utf-8")


def parse_asn_whois(response: str) -> dict:
    """Parse a bgp.tools ASN/IP whois response string into a dictionary."""
    try:
        fields, data = response.splitlines()
    except ValueError:
        LOGGER.warning("Unexpected bgp.tools response format:\n%r", response)
        raise ValueError("Unexpected bgp.tools response format")

    field_names = [field.strip().lower().replace(' ', '_') for field in fields.split('|')]
    field_values = [value.strip() for value in data.split('|')]

    if len(field_names) != len(field_values):
        LOGGER.warning("Mismatched field count in bgp.tools response:\n%r", response)
        raise ValueError("Mismatched field count in bgp.tools response")

    return dict(zip(field_names, field_values))


def parse_mac_whois(response: str) -> dict:
    """Parse a MAC address lookup response from bgp.tools into a dictionary."""
    if response.startswith("Vendor:\t"):
        return {'vendor': response.split('\t', 1)[1].strip()}
    else:
        LOGGER.warning("Unexpected MAC address response format:\n%r", response)
        raise ValueError("Unexpected MAC address response format")
