CC = ccache $(CROSS_COMPILE)gcc
CXX = ccache $(CROSS_COMPILE)g++
STRIP = $(CROSS_COMPILE)strip

CONFIG_MUSL_BUILD=y
CONFIG_STATIC_BUILD=y
DEBUG=n

INCLUDES = -I./include \
	   -I./include/libwebsockets

ifeq ($(CONFIG_MUSL_BUILD), y)
CROSS_COMPILE?= mipsel-openipc-linux-musl-
SDK_LIB_DIR = lib
LDFLAGS = -L./lib
#LDFLAGS = -L./lib -l:libwebsockets.a -lcjson
endif

ifeq ($(CONFIG_STATIC_BUILD), y)
LDFLAGS += -static
LWS = $(SDK_LIB_DIR)/libwebsockets.a
LDFLAGS += -L./lib -l:libwebsockets.a -lcjson
else
LWS = $(SDK_LIB_DIR)/libwebsockets.so
LDFLAGS = -L./lib -l:libwebsockets.so -lcjson
endif

ifeq ($(DEBUG), y)
CFLAGS += -g # Add -g for debugging symbols
STRIPCMD = @echo "Not stripping binary due to DEBUG mode."
else
STRIPCMD = $(STRIP)
endif

# Hardening flags
HARDENING_FLAGS = -D_FORTIFY_SOURCE=2 -fstack-protector-all -Wl,-z,relro,-z,now

CFLAGS = $(INCLUDES) -Wall -Wextra -O2 $(HARDENING_FLAGS)
BUILD_DIR = build
TARGET = $(BUILD_DIR)/web_command
SOURCES = web_command.c
OBJECTS = $(patsubst %.c,$(BUILD_DIR)/%.o,$(SOURCES))

.PHONY: all clean

all: $(BUILD_DIR) $(TARGET)

$(BUILD_DIR):
	mkdir -p $(BUILD_DIR)

$(TARGET): $(OBJECTS)
	$(CC) $(CFLAGS) -o $@ $^ $(LDFLAGS) $(LWS)
	$(STRIPCMD) $@

$(BUILD_DIR)/%.o: %.c
	$(CC) $(CFLAGS) -c $< -o $@

deps:
	mkdir lib include
	./scripts/make_cJSON_deps.sh
	./scripts/make_libwebsockets_deps.sh

clean:
	rm -rf $(BUILD_DIR)
	rm -rf lib
	rm -rf include
