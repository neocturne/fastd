all : fastd

fastd : fastd.o method_null.o task.o handshake.o queue.o
	$(CC) -o $@ $^ -lrt

fastd.o : fastd.c fastd.h task.h queue.h handshake.h
handshake.o : handshake.c packet.h handshake.h queue.h
method_null.o : method_null.c fastd.h task.h queue.h
task.o : task.c task.h queue.h
queue.o : queue.c queue.h

clean :
	rm -f fastd fastd.o handshake.o method_null.o task.o queue.o
