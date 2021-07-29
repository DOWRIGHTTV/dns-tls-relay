# DNS-over-TLS-Relay
<h2>stripped down dns relay (UDP > TCP/TLS) (privacy proxy)</h2><br>

<samp>usage: run_relay.py [-h] [--version] [-v] [-i IP_ADDRS] [-s SERVERS]<br><br>
Privacy proxy which converts DNS/UDP to TLS + local record caching.
optional arguments:<br><br>
  -h, --help                        show this help message and exit<br><br>
  --version                         show program's version number and exit<br><br>
  -v, --verbose                     prints output to screen<br><br>
  -i IP_ADDRS, --ip-addrs IP_ADDRS  comma separated ips to listen on<br><br>
  -s SERVERS, --servers SERVERS     comma separated ips of public DoT resolvers</samp><br><br>
  
<p><b>
Must be ran as root. listener interface defaults to loopback ip/127.0.0.1.
</b></p>

<p>
By default the public DNS Resolvers are set to CloudFlare. If you want to change, ensure the servers support DNS over TLS and are listening on ports TCP 853.
</p>

<p>
DNS over TLS time to resolve is anywhere from 3-5 times slower than standard UDP if a connection
to the remote resolver has not already been established or has timed out. The length in which the
remote end waits before closing depends on the resolvers used. Depending on the version of linux may dictate which TLS version is used. For example Ubuntu 19.04 contains the openssl version to support TLS 1.3. TLS 1.3 is preferred because the server certificate exchange is encrypted (this will have VERY minimal benefit with DoT) and some performance improvements to the protocol have been included.
</p>

<h3>Local Caching</h3>

<p>
All records will be cached for a minimum of 5 minutes to improve lan efficiency and reduce chatter over the WAN. The most requested domains on your network will be permanently cached (updated records retreived every 3 minutes) to guarantee a cached response for these domains.
</p>
