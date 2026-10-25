# Project 3 - Subnetting and Forwarding

- Name: Van Nguyen
- Email: vannguyen599@u.boisestate.edu
- Class: CS525

## Known Bugs or Issues

There are no known issues that I found. Functions are thoroughly tested and command line ran as expected. I created extra tables inside of `tables` directory to test it manually as well.
Below are the command lines that I ran to test and the returned value matched with what I expected.

```
./build/release/myapp info 192.168.1.0/24
./build/release/myapp lookup tables/example.txt 132.178.227.50 8.8.8.8 10.1.2.5
./build/release/myapp split 192.168.1.0/24 4

./build/release/myapp lookup tables/advance.txt 192.168.1.35 8.8.8.8 192.168.1.50
./build/release/myapp lookup tables/bad.txt 192.168.1.35

```


## Experience

In this project I used AI heavily and then I ran out of all tokens on my pro Copilot account, so another part of it was using Gemini Cli which I think is not as good but the logic was not that hard so the overall result turned out to be fine.

## Design


