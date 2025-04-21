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


OUTPUT_PREFIX = '[ASN] '
ENDPOINTS = {
    'origin': 'origin.asn.cymru.com',
    'origin6': 'origin6.asn.cymru.com',
    'peers': 'peer.asn.cymru.com',
    'asn': 'asn.cymru.com',
}


@plugin.commands('asn', 'asno', 'asnorigin', 'asnp', 'asnpeers')
@plugin.example('.asno 198.6.1.65')
@plugin.output_prefix(OUTPUT_PREFIX)
@plugin.rate(
    user=120,
    message="Please wait {time_left} before attempting another ASN lookup."
)
def get_asn_info(bot, trigger):
    """Look up ASN (Autonomous System Number) and routing information.

    All commands require an IP address or AS number (in `ASxxx` format) as the
    first & only argument.
    """
    if not (ip := trigger.group(3)):
        bot.reply("Please provide an IP address or ASN.")
        return plugin.NOLIMIT
    cmd = trigger.group(1).lower()

    try:
        ip = ipaddress.ip_address(ip)
    except (ValueError, ipaddress.AddressValueError):
        # treat as ASN
        if not re.match(r'^(AS)?\d+$', ip):
            bot.reply("Please provide a valid IP address or AS number.")
            return plugin.NOLIMIT
        if not ip.startswith('AS'):
            ip = 'AS' + ip
        lookup = ip
    else:
        if ip.version == 4:
            lookup = '.'.join([str(x) for x in reversed(ip.packed)])
        elif ip.version == 6:
            nibbles = [n for n in ip.packed.hex()]
            while nibbles[-1] == '0' and nibbles[-2] == '0':
                nibbles.pop()
                nibbles.pop()
            lookup = '.'.join([str(x) for x in reversed(nibbles)])

    if cmd in ('asn'):
        base = ENDPOINTS['asn']
    elif cmd in ('asno', 'asnorigin'):
        if ip.version == 4:
            base = ENDPOINTS['origin']
        elif ip.version == 6:
            base = ENDPOINTS['origin6']
        else:
            bot.reply("Invalid IP address version.")
            return plugin.NOLIMIT
    elif cmd in ('asnp', 'asnpeers'):
        base = ENDPOINTS['peers']
    else:
        bot.reply("Unrecognized command '{}'. How'd you get here?".format(cmd))
        return plugin.NOLIMIT

    lookup = '.'.join((lookup, base))
    responses = []

    try:
        answers = dns.resolver.resolve(lookup, 'TXT')
    except dns.exception.SyntaxError:
        bot.reply("That IP address doesn't seem to be valid.")
        return plugin.NOLIMIT
    except dns.exception.Timeout:
        bot.say("Lookup timed out for {}.".format(ip))
        return plugin.NOLIMIT
    except dns.resolver.NoNameservers:
        bot.say("Lookup attempted, but no nameservers were available.")
        return plugin.NOLIMIT
    except (dns.resolver.NXDOMAIN, dns.resolver.NoAnswer):
        bot.say("No records found for {}.".format(ip))
        return  # do rate-limit, since query succeeded

    if len(answers) > 0:
        for rdata in answers:
            responses.append(rdata.to_text())
    else:
        bot.say("Did not find any records for {}.".format(ip))
        return

    # Record types that should be handled one response per line
    for x in responses:
        bot.say(x)
