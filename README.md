wping
=====

Web daemon designed to test reachability of targets using ICMP Echo requests (aka. ping).

-----

Client specifies target using dst parameter for IPv4 destination specification and timeoutms for timeout.

  curl "http://localhost:8080/ping?dst=127.0.0.1&timeoutms=100"

***TODOS:***<br>
Add multiple packet handling<br>
Daemonize

-----

Bundled Software:

mongoose<br>
  Copyright (c) 2004-2013 Sergey Lyubka <valenok at gmail dot com><br> Copyright (c) 2013-2014 Cesanta Software Limited<br>

solarisfixes.h<br> 
  Copyright (c) 2009-2012, Salvatore Sanfilippo <antirez at gmail dot com>


