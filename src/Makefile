all : fastd

fastd : fastd.o method_null.o task.o handshake.o

fastd.o : fastd.c fastd.h task.h queue.h handshake.h
handshake.o : handshake.c packet.h handshake.h
method_null.o : method_null.c fastd.h task.h
task.o : task.c task.h queue.h

clean :
	rm -f fastd fastd.o method_null.o task.o
