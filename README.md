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
- if SOA record is returned in an non-authoritive answer, then use that DNS server to get the authoritive answer
- to lookup the domain name of an IP; the tool reverses the IP and adds .in-addr.arpa. So that 1.2.3.4 becomes 4.3.2.1.in-addr.arpa and request for PTR. Usage is `./dns 1.1.1.1 ptr` and it responds with `one.one.one.one`.

When doing investigations, it can involve multiple executions. For example if I want to explore the first top-level domain created on the internet `./dns arpa` makes a udp request and returns a soa record referring `a.root-servers.net` as dns server to use. A next execution is `./dns arpa any tcp a.root-servers.net` to get 44 authorative answers.

The `./dns arpa nsec udp a.root-servers.net ` is having 25 answers and record NSEC
contains a bitmap that encodes DNS record types. Output decodes this.


## to do

- brute force using a list of subdomain names
- brute force using a predefined list of subdomain names for domain controller
- improve command line argument handling
- better grepable output

## to do (win dc)

- dc srv records

https://social.technet.microsoft.com/wiki/contents/articles/7608.srv-records-registered-by-net-logon.aspx

https://learn.microsoft.com/en-us/troubleshoot/windows-server/networking/verify-srv-dns-records-have-been-created

## done

- extracted command line params
- multiple requests: `./dns github.com a,aaaa,cname,txt tcp |more` 
- dont stop when RCODE indicates an error, but show the remaining data
- improved RD RA text
- allow a name for the dns server instead of ip
- ptr lookup of ip
