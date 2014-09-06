#!/bin/sh
i686-w64-mingw32-g++ -DNDEBUG -std=c++11 -Wall -O2 -DWIN32 -mno-ms-bitfields -static -static-libgcc -I. ./client.cpp ./crypto/sha2.cpp -lwsock32 -lmingwthrd -o relaynetworkclient.exe &&
i686-w64-mingw32-strip relaynetworkclient.exe &&
mv relaynetworkclient.exe .. &&
g++ -DNDEBUG -std=c++11 -Wall -O2 -pthread -I. -I/usr/include ./client.cpp ./crypto/sha2.cpp -o relaynetworkclient &&
strip relaynetworkclient &&
mv relaynetworkclient ..
