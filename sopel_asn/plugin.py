"""sopel-asn

ASN lookup plugin for Sopel IRC bots

Copyright (c) 2025 dgw, technobabbl.es

Licensed under the Eiffel Forum License 2.
"""
from __future__ import annotations

from sopel import plugin

from .util import ASRecord, MACRecord


PREFIX = plugin.output_prefix('[ASN] ')


@plugin.commands('asn')
@plugin.example('.asn 208.67.222.222', user_help=True)
@plugin.example('.asn AS23028', user_help=True)
@PREFIX
@plugin.rate(
    user=30,
    message="Please wait {time_left} before attempting another ASN lookup."
)
def asn_command(bot, trigger):
    """Look up ASN (Autonomous System Number) and routing information.

    Requires an IP address or AS number (in `ASxxx` format) as the first (and
    only) argument.
    """
    if not (arg := trigger.group(3)):
        bot.reply("Please provide an IP address or ASN.")
        return plugin.NOLIMIT

    try:
        record: ASRecord = ASRecord.from_free_query(arg)
    except ValueError as e:
        bot.reply(str(e))
        return plugin.NOLIMIT

    bot.say(
        str(record),
        trailing=' | more info: https://bgp.tools/as/' + record.asn,
    )


@plugin.command('mac')
@plugin.example('.mac 00:1A:2B:3C:4D:5E', user_help=True)
@PREFIX
@plugin.rate(
    user=30,
    message="Please wait {time_left} before attempting another MAC lookup.",
)
def mac_command(bot, trigger):
    """Look up MAC address vendor information.

    Requires a MAC address as the first (and only) argument.
    """
    if not (arg := trigger.group(3)):
        bot.reply("Please provide a MAC address.")
        return plugin.NOLIMIT

    try:
        record: MACRecord = MACRecord.from_mac(arg)
    except ValueError as e:
        bot.reply(str(e))
        return plugin.NOLIMIT

    bot.say(f"MAC {record.mac} is registered to {record.vendor}.")
