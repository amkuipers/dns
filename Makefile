CC=gcc
objects = main.o connect.o hexdump.o dnstypes.o query.o

dns: $(objects) 
	 $(CC) -o dns $(objects)
	 chmod +x dns

run: dns
	./dns github.com

.PHONY : clean
clean :
	rm dns $(objects) a.out