### DNS Server

#### Returns WAN IP Address


When learning Python, this was my first project.

A bit more difficult than I expected! Bit-wise fiddling data read from socket,
I expected just a string of text.

It replaces the functionality found in a Slashdot user's signature for
finding out a network's WAN IP address via dig:

`dig my.ip @kwvoip.ca`


Extra functionality: block some ad servers and tracking sites. Add desired
sites to NXDOMAIN.list, and, unlike a pi-hole, which returns 0.0.0.0 for
ad servers, this returns a proper NXDOMAIN for "domain not found".



NOTE: this depends on python2 and needs some work, hasn't been used for several
years. It did function as expected in 2017 on Ubuntu.
