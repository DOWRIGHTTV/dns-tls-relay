# DNS-over-TLS-Relay
stripped down dns relay (UDP > TCP/TLS) (privacy proxy)

<code>
usage: run_relay.py [-h] [--version] [-v] [-i IP_ADDRS] [-s SERVERS]

Privacy proxy which converts DNS/UDP to TLS + local record caching.

optional arguments:

  -h, --help                        show this help message and exit

  --version                         show program's version number and exit

  -v, --verbose                     prints output to screen

  -i IP_ADDRS, --ip-addrs IP_ADDRS  comma separated ips to listen on

  -s SERVERS, --servers SERVERS     comma separated ips of public DoT resolvers
</code>

Must be ran as root. listener interface defaults to loopback ip/127.0.0.1.

By default the public DNS Resolvers are set to CloudFlare. If you want to change, ensure the servers support DNS over TLS and are listening on ports TCP 853.

DNS over TLS time to resolve is anywhere from 3-5 times slower than standard UDP if a connection
to the remote resolver has not already been established or has timed out. The length in which the
remote end waits before closing depends on the resolvers used. Depending on the version of linux may dictate which TLS version is used. For example Ubuntu 19.04 contains the openssl version to support TLS 1.3. TLS 1.3 is preferred because the server certificate exchange is encrypted (this will have VERY minimal benefit with DoT) and some performance improvements to the protocol have been included

Local Caching:

All records will be cached for a minimum of 5 minutes to improve lan efficiency and reduce chatter over the WAN. The mose requested domains on your network will be permanently cached (updated records retreived every 3 minutes) to ensure you will always receive a cached response for these domains.
