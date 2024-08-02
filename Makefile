## CentOS/Redhat:
# yum install openssl-devel
# yum install libcurl-devel
# yum install check                # Only need if you want to run tests

## Ubuntu:
# apt install build-essential
# apt install libssl-dev
# apt install libpcre3-dev
# apt install libcurl4-openssl-dev
# apt install check                # Only need if you want to run tests

CC = gcc
CFLAGS = -ggdb -O3 -Wall -Wno-deprecated
LIBS = -lpcre -lcrypto -lm -lpthread

OBJS = vanitygen.o oclvanitygen.o oclvanityminer.o oclengine.o keyconv.o pattern.o util.o groestl.o sha3.o ed25519.o \
       stellar.o base32.o crc16.o bech32.o segwit_addr.o simplevanitygen.o
PROGS = vanitygen++ keyconv oclvanitygen++ oclvanityminer

PLATFORM = $(shell uname -s)
ifeq ($(PLATFORM),Darwin)
	OPENCL_LIBS = -framework OpenCL
	LIBS += -L/usr/local/opt/openssl/lib
	CFLAGS += -I/usr/local/opt/openssl/include
else ifeq ($(PLATFORM),NetBSD)
	LIBS += `pcre-config --libs`
	CFLAGS += `pcre-config --cflags`
else
	OPENCL_LIBS = -lOpenCL
endif

most: vanitygen++ keyconv

all: $(PROGS)

vanitygen++: vanitygen.o pattern.o util.o groestl.o sha3.o ed25519.o stellar.o base32.o crc16.o simplevanitygen.o bech32.o segwit_addr.o
	$(CC) $^ -o $@ $(CFLAGS) $(LIBS)

oclvanitygen++: oclvanitygen.o oclengine.o pattern.o util.o groestl.o sha3.o
	$(CC) $^ -o $@ $(CFLAGS) $(LIBS) $(OPENCL_LIBS)

oclvanityminer: oclvanityminer.o oclengine.o pattern.o util.o groestl.o sha3.o
	$(CC) $^ -o $@ $(CFLAGS) $(LIBS) $(OPENCL_LIBS) -lcurl

keyconv: keyconv.o util.o groestl.o sha3.o
	$(CC) $^ -o $@ $(CFLAGS) $(LIBS)

run_tests.o: tests.h util_test.h segwit_addr_test.h pattern_test.h

run_tests: run_tests.o util.o groestl.o sha3.o bech32.o segwit_addr.o
	$(CC) $^ -o $@ $(CFLAGS) $(LIBS) $(OPENCL_LIBS) -lcheck

test: run_tests
	./run_tests

clean:
	rm -f $(OBJS) $(PROGS) $(TESTS) *.oclbin run_tests
