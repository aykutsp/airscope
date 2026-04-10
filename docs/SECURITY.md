# A note on responsible use

Airscope lets you passively observe 802.11 traffic, craft management
frames, and — on Linux with a supported card — transmit those frames
on a real radio. That last bit is what makes it a security tool, and
it's what makes it something you should think about before you run it.

## Do this

* Run it on networks you own.
* Run it as part of an engagement you're authorised to perform.
* Run it in an RF-isolated lab.
* Run it against pcaps you've collected under those conditions.

## Don't do this

* Don't deauth random clients at a coffee shop.
* Don't set up a rogue AP with a neighbour's SSID.
* Don't assume "I was just curious" is a defence. In most
  jurisdictions, transmitting 802.11 management frames on someone
  else's network is computer misuse or illegal radio interference.

Airscope does not contain cracking code. There is no WEP/WPA dictionary
attack, no EAPOL key reinjection against live clients, no PMKID dumper.
It's a visibility + analysis suite, not an offensive toolkit. The deauth
builder exists because deauthentication is also the test harness you
use when you're validating your own AP's roaming behaviour, not because
kicking strangers off the internet is clever.

If you find a bug that could be abused (e.g. an over-permissive parser
that could be triggered by a crafted frame), please open a private
advisory on the repo rather than a public issue.
