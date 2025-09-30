"""sopel-asn

ASN lookup plugin for Sopel IRC bots

Copyright (c) 2025 dgw, technobabbl.es

Licensed under the Eiffel Forum License 2.
"""
from __future__ import annotations

import dns.resolver

from sopel import plugin

from . import util


PREFIX = plugin.output_prefix('[ASN] ')


@plugin.commands('asn', 'asnp', 'asnpeers')
@plugin.example('.asnp 198.6.1.65', user_help=True)
@plugin.example('.asn 208.67.222.222', user_help=True)
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

    mode = 'asn'  # default mode
    cmd = trigger.group(1).lower()
    if cmd in ('asnp', 'asnpeers'):
        mode = 'peers'

    try:
        lookup = util.get_peer_lookup(arg) if mode == 'peers' else util.get_lookup(arg)
    except ValueError as e:
        bot.reply(str(e))
        return plugin.NOLIMIT

    if '.origin' in lookup:
        mode = 'origin'

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
            bot.say(util.format_record(rdata.to_text(), mode))
            return
    else:
        bot.say("Did not find any records for {}.".format(arg))
        return
