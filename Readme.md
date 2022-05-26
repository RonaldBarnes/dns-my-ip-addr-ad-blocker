### DNS Server

#### Returns WAN IP Address


When learning Python, this was my first project.

A bit more difficult than I expected! Bit-wise fiddling data read from socket,
I expected just a string of text.

It replaces the functionality found in a Slashdot user's signature for
finding out a network's WAN IP address via dig, now that the site
disappeared:

`dig my.ip @myoutsideip.net`


Extra functionality: block some ad servers and tracking sites. Add desired
sites to NXDOMAIN.list, and, unlike a pi-hole, which returns 0.0.0.0 for
ad servers, this returns a proper NXDOMAIN for "domain not found".

```
$ dig -p 53535 +short my.ip @kwvoip.ca
69.172.190.161
```

Or, full response:

```
$ dig -p 53535 my.ip @kwvoip.ca

; <<>> DiG 9.16.1-Ubuntu <<>> -p 53535 my.ip @kwvoip.ca
;; global options: +cmd
;; Got answer:
;; ->>HEADER<<- opcode: QUERY, status: NOERROR, id: 4497
;; flags: qr rd ra ad; QUERY: 1, ANSWER: 1, AUTHORITY: 0, ADDITIONAL: 1

;; QUESTION SECTION:
;my.ip.                         IN      A

;; ANSWER SECTION:
my.ip.                  0       IN      A       69.172.190.161

;; ADDITIONAL SECTION:
my.ip.                  86400   IN      TXT     "(c)" "Ronald Barnes" "2017"

;; Query time: 67 msec
;; SERVER: 199.212.143.222#53535(199.212.143.222)
;; WHEN: Thu May 26 15:00:54 PDT 2022
;; MSG SIZE  rcvd: 84
```




Reporting an ad server as non-existent:

```
$ dig -p 53535 doubleclick.net @kwvoip.ca

; <<>> DiG 9.16.1-Ubuntu <<>> -p 53535 doubleclick.net @kwvoip.ca
;; global options: +cmd
;; Got answer:
;; ->>HEADER<<- opcode: QUERY, status: NXDOMAIN, id: 29665
;; flags: qr rd ra ad; QUERY: 1, ANSWER: 0, AUTHORITY: 0, ADDITIONAL: 0
```

