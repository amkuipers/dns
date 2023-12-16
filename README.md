# dns

https://github.com/amkuipers/dns

DNS experiments in C. Code is still in development and requires refactoring and tests. 

Code can contain parts of
- "Hands-On Network Programming with C" written by Lewis Van Winkle, chapter 5, MIT license
- ChatGPT and GitHub CoPilot
- https://beej.us/guide/bgnet/html/index-wide.html#sendrecv
- https://en.wikipedia.org/wiki/List_of_DNS_record_types
- https://blog.cloudflare.com/rfc8482-saying-goodbye-to-any

## build

- Run `make` and it produces an executable named `dns`
- Run `make clean` to remove object files and the executable
- Run `make run` and it builds and then makes an actual call

It works when building on Apple M3 Pro.
The github repo contains a build pipeline (see Actions https://github.com/amkuipers/dns/actions ) that builds it too,
but the result is not monitored all the time.

## bugs and other remarks

- not all record type answers are implemented, the default is then to hexdump the answer
- in case not all answers are printed and end with an error; add hexdump call to the answer to investigate and fix. 

## tips

- when requesting udp, the udp response with TC 1 means it is truncated, and you should do a tcp request instead to get the information. Reason is that the answer does not fit in the udp response, and it does in a tcp response.
- sometimes ANY returns records, but most of the time a HINFO referencing an RFC is returned, basically stating that the server deprecated the ANY implementation. I did experience that the same dns once in a while does return a long list of answers on ANY.

## to do

- brute force using a list of subdomain names
- brute force using a predefined list of subdomain names for domain controller
- improve command line argument handling
- allow a name for the dns server instead of ip

## done

- extracted command line
- multiple requests: `./dns github.com a,aaaa,cname,txt tcp |more` 
