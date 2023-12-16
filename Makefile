CC=gcc
objects = main.o connect.o hexdump.o dnstypes.o query.o base64.o timestamp.o print.o

dns: $(objects) 
	 $(CC) -o dns $(objects)
	 chmod +x dns

run: dns
	./dns github.com any tcp 8.8.8.8

.PHONY : clean
clean :
	rm dns $(objects) a.out