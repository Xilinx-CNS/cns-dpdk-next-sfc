CROSS_COMPILE = aarch64-linux-gnu-
CC = $(CROSS_COMPILE)gcc
CFLAGS = -Wall -O
LDLIBS = -lmcdi

STATIC = libmcdi.a
.PHONY: all
all: mcdi_app mcdi_init

.PHONY: clean
clean:
	$(RM) *~ *.o mcdi_app mcdi_init libmcdi.a

APP_OBJECTS=mcdi_send_receive_app.o
INIT_APP_SRC=mcdi_init_app.c

mcdi_app: $(APP_OBJECTS) $(STATIC)
	$(CC) $(CFLAGS) $(APP_OBJECTS) $(LDLIBS) -L. -o $@

mcdi_init:
	 $(CC) $(CFLAGS) $(INIT_APP_SRC) -o $@

libmcdi.a: mcdi_lib.o
	$(RM) $@
	$(CROSS_COMPILE)ar rcs $@ $^

libs: libmcdi.a
