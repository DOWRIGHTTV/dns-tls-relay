# DNS-over-TLS-Relay
stripped down dns relay (UDP > TCP/TLS) (privacy proxy)

TO USE:

CHANGE (in dns_tls_relay.py):

LISTENING_ADDRESS > local address on device. if using a system like pi-hole, this should be 127.0.0.1
CLIENT_ADDRESS > local address on device with internet access

By default the Public DNS Resolvers are set to CloudFlare. If you want to change, ensure the servers support
DNS over TLS and are listening on ports TCP 853.
PUBLIC_SERVER_1 = '1.1.1.1'
PUBLIC_SERVER_2 = '1.0.0.1'

NOTES:
DNS over TLS time to resolve is anywhere from 3-5 times slower than standard UDP.
Depending on the version of linux will depend on which TLS version is used. For example Ubuntu 19.04 contains
    the openssl version to support TLS 1.3. TLS 1.3 is preferred because even the ssl certificate is encrypted.

Local Caching:
All records will be cached for a minimum of 5 minutes to improve performance.
The mose requested domains on your network will be permanently cached (checked every 5 minutes) to ensure you will
    always receive a cached response for these domains. (the system will ensure the records are up to date in the background)


TO RUN:
navigate to the folder where the files are located.
run the following command

sudo python3 dns_tls_relay.py (priveleged port in use so admin rights are required)
