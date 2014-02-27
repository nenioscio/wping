wping
=====

Web daemon designed to test reachability of targets using ICMP Echo requests (aka. ping).

-----

Client specifies target using dst parameter for IPv4 destination specification and timeoutms for timeout.

  ```curl "http://localhost:8080/ping?dst=reachable&timeoutms=100"```

```
Destination alive: 1
Icmp_response_type: 0
Icmp_response_code: 0

```

Daemon is designed to provide json output if request (Accept header):

  ```curl -H "Accept: application/json" "http://localhost:8080/ping?dst=reachable&timeoutms=100"```

```
{"status": true, "status_message": "", "icmp_type": 0, "icmp_code": 0}
```

***TODOS:***<br>
*   Add multiple packet handling

*   Daemonize


-----

Bundled Software:

*   solarisfixes.h

    Copyright (c) 2009-2012, Salvatore Sanfilippo &lt;antirez at gmail dot com&gt;

