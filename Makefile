CEXT_NAME=cjson

CC?=clang
CFLAGS+=-isystem include -fPIC -Wbuiltin-declaration-mismatch -Wimplicit-function-declaration
DEBUG_FLAGS=-g -O0
PRODUCTION_FLAGS=-O2

DYLIB_CFLAGS?=-shared

SYS:=$(shell ${CC} -dumpmachine)
ifneq ($(findstring linux, $(SYS)),)
    DYLIB_PATH=native/linux-amd64/
    DYLIB_EXTENSION=.so
else ifneq ($(findstring mingw, $(SYS)),)
    CFLAGS+=--sysroot=$(MINGW_DIR) -fuse-ld=lld
    EXEC_CFLAGS=-mconsole
    EXEC_EXTENSION=.exe
    DYLIB_PATH=native/windows-amd64
    DYLIB_EXTENSION=.dll
else ifneq ($(findstring cygwin, $(SYS)),)
    # Do Cygwin things
else ifneq ($(findstring darwin, $(SYS)),)
    CFLAGS+=-arch arm64 -Wimplicit-int -Wc2x-extensions -Wdeprecated-non-prototype
    CFLAGS+=-arch x86_64
    DYLIB_PATH=native/macos/
    DYLIB_EXTENSION=.dylib
endif

build: build-production

build-production: create-dirs $(CEXT_NAME).c
	$(CC) $(PRODUCTION_FLAGS) $(CFLAGS) ${DYLIB_CFLAGS} -o build/$(DYLIB_PATH)$(CEXT_NAME)$(DYLIB_EXTENSION) $(CEXT_NAME).c

create-dirs:
	mkdir -p build/bin
	mkdir -p build/$(DYLIB_PATH)

clean:
	rm -fr build/
