# DNS-over-TLS-Relay
<body>
  <h2>
    Privacy proxy converting DNS:UDP to TLS
  </h2>
  <br>
  <p>
    <b>Must be ran as root.</b>
  </p>
  <samp>
    usage: run_relay.py [-h] [--version] [-l listen_ip [listen_ip...]]
                    [-r resolver_ip resolver_ip] [-k {4,6,8}] [-c] [-v]
  </samp>
  <br><br>
  <samp>
    optional arguments:<br>
    <p style="margin-left: 40px">
      -h, --help            show this help message and exit<br><br>
      --version             show program's version number and exit<br><br>
      -l ip_addr [ip_addr...]
                        List of IP Addresses to listen for requests on<br><br>
      -r ip_addr ip_addr    List of (2) IP Addresses of desired public DoT
                        resolvers<br><br>
      -k {4,6,8}            Enables TLS connection keepalives<br><br>
      -c                    Prints general messages to screen<br><br>
      -v                    Prints informational messages to screen
    </p>
  </samp>
  <h3>Details</h3>
  <p>
    If a listener ip address is not specified, the relay will fallback to the loopback interface [127.0.0.1].
  </p>
  <p>
    DNS over TLS time to resolve is slower than standard UDP <b><i>if a connection to the remote resolver has not already 
    been established</i></b>. The length in which the remote end waits before closing (timing out due to inactivity) 
    depends on the resolvers set. Based on general analysis, DNS queries tend to group up as a side effect of system and 
    relay record caching. Because of this, timeouts are more likely even if the requests per second average is within the 
    timeout threshold. To offset this, a keepalive option is available on 4, 6, or 8 second intervals which will send a 
    query to the public resolver to reset its timeout interval.
  </p>
  <p>
    <b>info:</b> By default the public DNS resolvers are set to Cloudflare. If you want to override the default, ensure 
    the servers support DNS over TLS and are listening on ports TCP 853.
  </p>
  <h3>Local Caching</h3>
  <p>
    All records will be cached for a minimum of 5 minutes to improve lan efficiency and reduce chatter over the WAN. The 
    most requested domains on your network will be permanently cached (updated records retrieved every 3 minutes) to 
    guarantee a cached response for these domains.
  </p>
  <p>
    <b>note:</b> <i>The minimum ttl length can cause issues with CDNs in rare cases where its IPs revolve in shorter 
    intervals than the minimum ttl. This can be fixed by modfying the constant values in the constants.py file. In the 
    near future this will be added as a program argument so file editing wont be necessary.</i>
  </p>
</body>