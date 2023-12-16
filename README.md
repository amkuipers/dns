# dns
DNS experiments in C. Code is still in development and requires refactoring and tests. 

Code can contain parts of
- "Hands-On Network Programming with C" written by Lewis Van Winkle, chapter 5, MIT license
- ChatGPT and GitHub CoPilot
- https://beej.us/guide/bgnet/html/index-wide.html#sendrecv
- https://en.wikipedia.org/wiki/List_of_DNS_record_types

## build

- Run `make` and it produces an executable named `dns`
- Run `make clean` to remove object files and the executable
- Run `make run` and it builds and then makes an actual call

It works when building on Apple M3 Pro.
The github repo contains a build pipeline that builds it too, but the
result is not monitored all the time.
