NCPH
====

"No Connection Parameters Here" is designed to help find a usable IP (and hopefully some other parameters) when connecting to a network of unknown topology and without any sort of DHCP services.  It's written in Ruby and uses the lovely PacketFu gem to stitch together a variety of datagrams.

General operation should be as follows (although all of these steps are not fully implemented yet):

- Listen to ARP traffic on the connceted interface to determine which hosts exist on the network
- Use the ARP-ed addresses to build a probable network address and netmask for the connected network
- Pick a random, not-yet-seen address from that range and check for IP conflict in a nonintrusive manner (hopefully following RFC5227)
- Assign that IP address to the connected interface
- Presuming the most-ARPed-for address to be the default gateway, test connectivity through that
