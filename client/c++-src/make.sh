#!/bin/sh
DEFINES=""
[ "$1" = "test" ] && DEFINES="-DFOR_VALGRIND -g" || DEFINES="-DNDEBUG -O2"

( g++ $DEFINES -std=c++11 -Wall -pthread -I. -I/usr/include ./client.cpp ./crypto/sha2.cpp -o relaynetworkclient &&
( [ "$1" != "test" ] && strip relaynetworkclient || echo -n ) &&
mv relaynetworkclient .. ) || echo "Failed to build using g++"

( i686-w64-mingw32-g++ $DEFINES -std=c++11 -Wall -DWIN32 -mno-ms-bitfields -static -static-libgcc -I. ./client.cpp ./crypto/sha2.cpp -lwsock32 -lmingwthrd -o relaynetworkclient.exe &&
( [ "$1" != "test" ] && i686-w64-mingw32-strip relaynetworkclient.exe || echo -n ) &&
mv relaynetworkclient.exe .. ) || echo "Failed to build windows client with mingw"
