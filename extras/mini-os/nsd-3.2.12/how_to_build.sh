gcc -I. -I. -g -O2 -c answer.c
gcc -I. -I. -g -O2 -c axfr.c
gcc -I. -I. -g -O2 -c buffer.c
gcc -I. -I. -g -O2 -c configlexer.c
gcc -I. -I. -g -O2 -c configparser.c
gcc -I. -I. -g -O2 -c options.c
gcc -I. -I. -g -O2 -c dbaccess.c
gcc -I. -I. -g -O2 -c difffile.c
gcc -I. -I. -g -O2 -c dname.c
gcc -I. -I. -g -O2 -c dns.c
gcc -I. -I. -g -O2 -c edns.c
gcc -I. -I. -g -O2 -c ipc.c
gcc -I. -I. -g -O2 -c iterated_hash.c
gcc -I. -I. -g -O2 -c namedb.c
gcc -I. -I. -g -O2 -c netio.c
gcc -I. -I. -g -O2 -c nsd.c
gcc -I. -I. -g -O2 -c nsec3.c
gcc -I. -I. -g -O2 -c packet.c
gcc -I. -I. -g -O2 -c query.c
gcc -I. -I. -g -O2 -c rbtree.c
gcc -I. -I. -g -O2 -c rdata.c
gcc -I. -I. -g -O2 -c region-allocator.c
gcc -I. -I. -g -O2 -c server.c
gcc -I. -I. -g -O2 -c tsig.c
gcc -I. -I. -g -O2 -c tsig-openssl.c
gcc -I. -I. -g -O2 -c util.c
gcc -I. -I. -g -O2 -c xfrd-disk.c
gcc -I. -I. -g -O2 -c xfrd-notify.c
gcc -I. -I. -g -O2 -c xfrd-tcp.c
gcc -I. -I. -g -O2 -c xfrd.c
gcc -I. -I. -g -O2 -c ./compat/strlcat.c -o strlcat.o
gcc -I. -I. -g -O2 -c ./compat/strlcpy.c -o strlcpy.o
gcc -I. -I. -g -O2 -c ./compat/b64_pton.c -o b64_pton.o
gcc -I. -I. -g -O2 -c ./compat/b64_ntop.c -o b64_ntop.o
gcc -g -O2  -o nsd answer.o axfr.o buffer.o configlexer.o configparser.o options.o dbaccess.o difffile.o dname.o dns.o edns.o ipc.o iterated_hash.o namedb.o netio.o nsd.o nsec3.o packet.o query.o rbtree.o rdata.o region-allocator.o server.o tsig.o tsig-openssl.o util.o xfrd-disk.o xfrd-notify.o xfrd-tcp.o xfrd.o strlcat.o strlcpy.o b64_pton.o b64_ntop.o 
