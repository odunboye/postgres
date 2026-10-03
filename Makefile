CC ?= cc
CFLAGS ?= -O2 -Wall -Wextra -Werror -std=c11
PKG_CONFIG ?= pkg-config
OPENSSL_CFLAGS := $(shell $(PKG_CONFIG) --cflags openssl)
OPENSSL_LIBS := $(shell $(PKG_CONFIG) --libs openssl)
ifeq ($(shell uname -s),Darwin)
SHARED_FLAGS = -dynamiclib
SUFFIX = dylib
else
SHARED_FLAGS = -shared -fPIC
SUFFIX = so
endif
.PHONY: native
native:
	$(PKG_CONFIG) --atleast-version=3.0.0 openssl
	mkdir -p lib
	$(CC) $(CFLAGS) $(OPENSSL_CFLAGS) $(SHARED_FLAGS) c/pg_transport.c c/pg_tls.c -o lib/libidris2_pg_transport.$(SUFFIX) $(OPENSSL_LIBS)
