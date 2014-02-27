wping
=====

Web daemon designed to test reachability of targets using ICMP Echo requests (aka. ping).

-----

Client specifies target using dst parameter for IPv4 destination specification and timeoutms for timeout.

  curl "http://localhost:8080/ping?dst=127.0.0.1&timeoutms=100"

***TODOS:***<br>
*   Add multiple packet handling

*   Daemonize

*   Add json output

-----

Bundled Software:

*   mongoose

    Copyright (c) 2004-2013 Sergey Lyubka &lt;valenok at gmail dot com&gt;<br>Copyright (c) 2013-2014 Cesanta Software Limited

*   solarisfixes.h

    Copyright (c) 2009-2012, Salvatore Sanfilippo &lt;antirez at gmail dot com&gt;

