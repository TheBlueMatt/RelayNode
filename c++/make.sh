#!/bin/bash
set -e

DEFINES=""
[ "$1" = "test" ] && DEFINES="-DFOR_VALGRIND -g" || DEFINES="-DNDEBUG -O2"

[ "$1" = "x86_bsd" ] && DEFINES="$DEFINES -DX86_BSD"

( g++ $DEFINES -std=c++11 -Wall -pthread -I. -I/usr/include ./client.cpp ./crypto/sha2.cpp -o relaynetworkclient &&
( [ "$1" != "test" ] && strip relaynetworkclient || echo -n ) &&
mv relaynetworkclient ../client ) || ( echo "Failed to build local client using g++"; exit -1 )

( g++ $DEFINES -std=c++11 -Wall -pthread -I. -I/usr/include ./bitcoindterminator.cpp ./crypto/sha2.cpp -o relaynetworkterminator &&
( [ "$1" != "test" ] && strip relaynetworkterminator || echo -n ) &&
mv relaynetworkterminator .. ) || ( echo "Failed to build server terminator using g++"; exit -1 )

( i686-w64-mingw32-g++ $DEFINES -std=c++11 -Wall -DWIN32 -mno-ms-bitfields -static -static-libgcc -I. ./client.cpp ./crypto/sha2.cpp -lwsock32 -lmingwthrd -o relaynetworkclient.exe &&
( [ "$1" != "test" ] && i686-w64-mingw32-strip relaynetworkclient.exe || echo -n ) &&
mv relaynetworkclient.exe ../client ) || ( echo "Failed to build windows client with mingw"; exit -1 )
