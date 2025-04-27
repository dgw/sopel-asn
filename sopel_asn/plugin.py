"""sopel-asn

ASN lookup plugin for Sopel IRC bots

Copyright (c) 2025 dgw, technobabbl.es

Licensed under the Eiffel Forum License 2.
"""
from __future__ import annotations

import ipaddress
import re

import dns.resolver

from sopel import plugin


PREFIX = plugin.output_prefix('[ASN] ')
ENDPOINTS = {
    'origin': 'origin.asn.cymru.com',
    'origin6': 'origin6.asn.cymru.com',
    'peers': 'peer.asn.cymru.com',
    # there is no peer6 interface, as far as I can tell
    # queries with both nibbles and bytes return nothing
    'asn': 'asn.cymru.com',
}


@plugin.commands('asn', 'asno', 'asnorigin', 'asnp', 'asnpeers')
@plugin.example('.asno 198.6.1.65', user_help=True)
@plugin.example('.asn AS23028', user_help=True)
@PREFIX
@plugin.rate(
    user=30,
    message="Please wait {time_left} before attempting another ASN lookup."
)
def asn_commands(bot, trigger):
    """Look up ASN (Autonomous System Number) and routing information.

    All commands require an IP address or AS number (in `ASxxx` format) as the
    first & only argument.
    """
    if not (arg := trigger.group(3)):
        bot.reply("Please provide an IP address or ASN.")
        return plugin.NOLIMIT
    cmd = trigger.group(1).lower()

    if cmd in ('asn'):
        mode = 'asn'
        base = ENDPOINTS['asn']
    elif cmd in ('asno', 'asnorigin'):
        mode = 'origin'
    elif cmd in ('asnp', 'asnpeers'):
        mode = 'peers'
        base = ENDPOINTS['peers']
    else:
        bot.reply("Unrecognized command '{}'. How'd you get here?".format(cmd))
        return plugin.NOLIMIT

    if mode == 'asn':
        # validate input as AS number
        arg = arg.upper()  # ensure "AS" prefix is uppercase, if present
        if not re.match(r'^(AS)?\d+$', arg):
            bot.reply("{} is not an AS number.".format(arg))
            return plugin.NOLIMIT
        if not arg.startswith('AS'):
            arg = 'AS' + arg
        lookup = arg
    else:
        # validate input as IP address
        try:
            arg = ipaddress.ip_address(arg)
        except (ValueError, ipaddress.AddressValueError):
            bot.reply("{} is not a valid IP address.".format(arg))
            return plugin.NOLIMIT
        else:
            if arg.version == 4:
                lookup = '.'.join([str(x) for x in reversed(arg.packed)])
            elif arg.version == 6:
                nibbles = [n for n in arg.packed.hex()]
                while nibbles[-1] == '0' and nibbles[-2] == '0':
                    nibbles.pop()
                    nibbles.pop()
                lookup = '.'.join([str(x) for x in reversed(nibbles)])

    if type(arg) != str and mode == 'origin':
        # non-string = IP address; ASN stays as a str
        if arg.version == 4:
            base = ENDPOINTS['origin']
        elif arg.version == 6:
            base = ENDPOINTS['origin6']
        else:
            bot.reply("Invalid IP address version.")
            return plugin.NOLIMIT

    lookup = '.'.join((lookup, base))
    responses = []

    try:
        answers = dns.resolver.resolve(lookup, 'TXT')
    except dns.exception.SyntaxError:
        bot.reply("That IP address doesn't seem to be valid.")
        return plugin.NOLIMIT
    except dns.exception.Timeout:
        bot.say("Lookup timed out for {}.".format(arg))
        return plugin.NOLIMIT
    except dns.resolver.NoNameservers:
        bot.say("Lookup attempted, but no nameservers were available.")
        return plugin.NOLIMIT
    except (dns.resolver.NXDOMAIN, dns.resolver.NoAnswer):
        bot.say("No records found for {}.".format(arg))
        return  # do rate-limit, since query succeeded

    if len(answers) > 0:
        for rdata in answers:
            responses.append(rdata.to_text())
    else:
        bot.say("Did not find any records for {}.".format(arg))
        return

    # Record types that should be handled one response per line
    for x in responses:
        bot.say(format_record(x, mode))


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
