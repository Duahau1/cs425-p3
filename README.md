# Project 3 - Subnetting and Forwarding

- Name: Van Nguyen
- Email: vannguyen599@u.boisestate.edu
- Class: CS525

## Known Bugs or Issues

There are no known issues that I found. Functions are thoroughly tested and command lines ran as expected. I created extra tables inside of `tables` directory to test it manually as well.
Below are the command lines that I ran to test and the returned value matched with what I expected.

```
./build/release/myapp info 192.168.1.0/24
./build/release/myapp lookup tables/example.txt 132.178.227.50 8.8.8.8 10.1.2.5
./build/release/myapp split 192.168.1.0/24 4

./build/release/myapp lookup tables/advance.txt 192.168.1.35 8.8.8.8 192.168.1.50
./build/release/myapp lookup tables/bad.txt 192.168.1.35

```

Test passed with 100% coverage with no leak.

## Experience

In this project I used AI heavily and then I ran out of all tokens on my pro Copilot account. Since it is almost the end of the month so I decided to upgraded my account and used Gemini instead which I think is not as good but the logic was not that hard so the overall result turned out to be fine. The project would have take 4 hours longer if I did not use AI, but thanks to AI it only took me like 3 hours to finish the whole thing.

## Design

The implementation is organized around the three parts of the project: address and CIDR handling, subnet arithmetic, and forwarding-table lookup. The public types and function declarations are in `src/lab.h`; the implementation is in `src/lab.c`. IPv4 addresses are stored in a `uint32_t` with the first octet in the most significant byte, which keeps parsing, formatting, masking, and comparisons consistent.

Address and CIDR parsing validate input before writing to the caller's output. Decimal values are parsed digit by digit, rejecting malformed values, leading zeroes, and values above the permitted range. Subnet operations use a mask derived from the prefix. Host-count and host-address functions handle `/31` and `/32` separately, avoiding the usual network and broadcast assumptions for those prefixes.

The forwarding table is opaque to callers and stores routes in a dynamically growing array. Route parsing validates the destination, gateway, and device fields; table loading removes comments, skips blank lines, and stops at the first invalid route while reporting its line number. Lookup scans matching routes and returns the one with the longest prefix, so more specific routes take precedence over a default route.
