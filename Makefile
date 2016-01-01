ping: ping.c
	gcc ping.c -o ping -lpthread
clean:
	rm -rf ping
