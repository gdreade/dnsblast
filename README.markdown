DNSBlast
========

`dnsblast` is a simple and really stupid load testing tool for DNS resolvers.

Give it the IP address of a resolver, the total number of queries you
want to send, the rate (number of packets per second), and `dnsblast`
will tell you how well the resolver is able to keep up.

What it is:
-----------

- a tool to spot bugs in DNS resolvers.
- a tool to help you tune and tweak DNS resolver code in order to
improve it in some way.
- a tool to help you tune and tweak the operating system so that it
can properly cope with a slew of UDP packets.
- a tool to test a resolver with real queries sent to the real and
scary interwebz, not to a sandbox.

What it is not:
---------------

- a tool for DoS'ing resolvers. There are way more efficient ways to
achieve this.
- a benchmarking tool.
- a tool for testing anything but how the server behaves under load.
If you need a serious test suite, take a look at what Unbound
provides.

What it does:
-------------

It sends queries for names like
`<random char><random char><random char><random char>.com`.

Yes, that's 4 random characters dot com (or with another domain if
you so specify). Doing that achieves a
NXDOMAIN vs "oh cool, we got a reply" ratio that is surprisingly close
to the one you get from real queries made by real users.

Oh, and it displays that:

    Sent: [1000] - Received: [799] - Reply rate: [250 pps] - Ratio: [79.90%]

That's the number of packets that have been sent, how many have been
received (if everything is fine, both values should be the same), how
fast the server replies, and the ratio between received and sent
queries.

Different query types are sent. Namely SOA, A, AAAA, MX and TXT, and
the probability that a query type gets picked is also close to its
probability in the real world.

Names are occasionally repeated, also to get closer to what happens in
the real world. That triggers resolver code responsible for queuing
and merging queries.

The test is deterministic: the exact same sequence of packets is sent
every time you fire up `dnsblast`. The magic resides in the power of
the `rand()` function with a fixed seed.

What it does not:
-----------------

It doesn't support DNSSEC, it doesn't send anything using TCP, it
doesn't pay attention to the content the resolver sents.

Fuzzing:
--------

In addition, `dnsblast` can send malformed queries.

Most resolvers just ignore these, so don't expect a high
replies/queries ratio. But this feature can also help spotting bugs.

The fuzzer is really, really, really simple, though. It just changes
some random bytes. It doesn't even pay attention to the server's
behavior.

How do I compile it?
--------------------

Type: `make`.

The code it trivial and should be fairly portable, although it only
gets tested on OSX and OpenBSD.

How do I use it?
----------------

Read the man page.  However, some examples follow for the curious.

To send a shitload of queries to 127.0.0.1:

    dnsblast 127.0.0.1

To send 50,000 queries to 127.0.0.1:

    dnsblast -c 50000 127.0.0.1

To send 50,000 queries at a rate of 100 queries per second:

    dnsblast -c 50000 -r 100 127.0.0.1

To send 50,000 queries at a rate of 100 qps to a non standard-port, like 5353:

    dnsblast -c 50000 -r 100 -p 5353 127.0.0.1

To send malformed packets, use the -F ("fuzz") flag:

    dnsblast -F 127.0.0.1

To use a different domain for the queries, which can be useful if you
want to run this against an authoritive nameserver without impacting 
anything else on the Internet, try the following.  Note the leading
dot on the domain name:

    dnsblast -d .example.com 127.0.0.1

To send from a range of IPs (IPv4 only):

    dnsblast -R 192.168.99.201:192.168.99.220 127.0.0.1

Note that for that last one, you either have to have those source IPs
associated with your machine or you have to run as root and be on an
operating system that supports binding to non-local IPs.
