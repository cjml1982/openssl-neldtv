CC = gcc
PROM = newtest
CFLAGS = -I../../ -I../../include -I./
LDFLAGS = -L../../ -Wl,-rpath,../../
LIBS = -lcrypto -lpthread -ldl

OBJECTS = pthread_pool.o test_for_all.o

$(PROM) : $(OBJECTS)
	$(CC) -g -o $(PROM) $(OBJECTS) $(LIBS) $(LDFLAGS)

pthread_pool.o : pthread_pool.c pthread_pool.h
	$(CC) -g -c pthread_pool.c

test_for_all.o : test_for_all.c
	$(CC) -g -c test_for_all.c $(CFLAGS) 


.PHONY : clean
clean: 
	rm $(PROM) $(OBJECTS)
