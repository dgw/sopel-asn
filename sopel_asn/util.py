"""Utility functions for sopel-asn."""
from __future__ import annotations

import ipaddress


ENDPOINTS = {
    'origin': 'origin.asn.cymru.com',
    'origin6': 'origin6.asn.cymru.com',
    'peers': 'peer.asn.cymru.com',
    # there is no peer6 interface, as far as I can tell
    # queries with both nibbles and bytes return nothing
    'asn': 'asn.cymru.com',
}


def get_lookup(arg: str | ipaddress.IPv4Address | ipaddress.IPv6Address) -> str:
    """Get the appropriate lookup string for an IP address or AS number.

    :param arg: An IP address (as a string or ``ipaddress`` object) or AS number
                (as a string, in ``ASxxx`` format).
    :return: The lookup string to use for querying Cymru's DNS service.

    :raise ValueError: If the input is not a valid IP address or AS number.
    """
    if isinstance(arg, (ipaddress.IPv4Address, ipaddress.IPv6Address)):
        ip = arg
    else:
        try:
            ip = ipaddress.ip_address(arg)
        except ValueError:
            # not an IP address; check if it's an AS number
            arg = arg.upper()  # ensure "AS" prefix is uppercase, if present
            if not arg.startswith('AS'):
                arg = 'AS' + arg
            if not arg[2:].isdigit():
                raise ValueError(f"{arg} is not a valid IP address or AS number.")

            return arg + '.' + ENDPOINTS['asn']

    # it's an IP address; convert to the appropriate lookup format
    if ip.version == 4:
        return '.'.join(
            reversed(ip.exploded.split('.'))
        ) + '.' + ENDPOINTS['origin']
    elif ip.version == 6:
        nibbles = list(ip.exploded.replace(':', ''))
        while nibbles[-1] == '0' and nibbles[-2] == '0':
            nibbles.pop()
            nibbles.pop()
        return '.'.join(reversed(nibbles)) + '.' + ENDPOINTS['origin6']
    else:
        raise ValueError(f"{arg} is not a valid IP address or AS number.")


def get_peer_lookup(arg: str | ipaddress.IPv4Address) -> str:
    """Get the appropriate lookup string for an IP address for peer queries.

    :param arg: An IP address (as a string or ``ipaddress`` object).
    :return: The lookup string to use for querying Cymru's DNS service for peers.
    :raise ValueError: If the input is not a valid IPv4 address.

    Note: Cymru does not appear to maintain a lookup service for IPv6 peers.
    """
    if isinstance(arg, ipaddress.IPv4Address):
        ip = arg
    else:
        try:
            ip = ipaddress.ip_address(arg)
        except ValueError:
            raise ValueError(f"{arg} is not a valid IPv4 address.")
        if ip.version != 4:
            raise ValueError(f"{arg} is not a valid IPv4 address.")

    return '.'.join(
        reversed(ip.exploded.split('.'))
    ) + '.' + ENDPOINTS['peers']


def format_record(record: str, mode: str) -> str:
    """Format a DNS record for display."""
    record = record.strip('"')
    parts = [part.strip() for part in record.split(' | ')]

    if mode == 'asn':
        # the ASN record fields are:
        # number | country_code | registry | registration_date | AS_name
        return (
            "AS{number} | {name} | {country} | Registered at {registry} on {regdate}"
        ).format(
            number=parts[0],
            name=parts[4],
            country=parts[1],
            registry=parts[2],
            regdate=parts[3],
        )
    elif mode == 'origin':
        # origin record fields are:
        # number | prefix | country_code | registry | registration_date
        return (
            "AS{number} | {prefix} | {country} | Registered at {registry} on {regdate}"
        ).format(
            number=parts[0],
            prefix=parts[1],
            country=parts[2],
            registry=parts[3],
            regdate=parts[4],
        )
    elif mode == 'peers':
        # peer record fields are:
        # peer_ASNs (space separated) | prefix | country_code | registry | registration_date
        return (
            "{prefix} | {country} | Registered at {registry} on {regdate} | Peer ASNs: {peers}"
        ).format(
            prefix=parts[1],
            peers=', '.join(parts[0].split()),
            country=parts[2],
            registry=parts[3],
            regdate=parts[4],
        )
    else:
        # fallback to the raw record for unrecognized modes
        return record
