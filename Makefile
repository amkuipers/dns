CC=gcc
objects = main.o

dns: $(objects) 
     $(CC) -o dns $(objects)
	 chmod +x dns
	 ./dns github.com
	 