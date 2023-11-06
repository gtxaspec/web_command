CC = ccache $(CROSS_COMPILE)gcc
CXX = ccache $(CROSS_COMPILE)g++
STRIP = $(CROSS_COMPILE)strip

CONFIG_MUSL_BUILD=y
CONFIG_STATIC_BUILD=y

INCLUDES = -I./include \
	   -I./include/libwebsockets

ifeq ($(CONFIG_MUSL_BUILD), y)
CROSS_COMPILE?= mipsel-openipc-linux-musl-
#CROSS_COMPILE?= arm-openipc-linux-musleabihf-
SDK_LIB_DIR = lib
LDFLAGS = -L./lib -l:libwebsockets.a -lcjson
endif

ifeq ($(CONFIG_STATIC_BUILD), y)
LDFLAGS += -static
LWS = $(SDK_LIB_DIR)/libwebsockets.a
#else
#LWS = $(SDK_LIB_DIR)/libwebsockets.so
endif

CFLAGS = $(INCLUDES) -Wall -Wextra -O2
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

$(BUILD_DIR)/%.o: %.c
	$(CC) $(CFLAGS) -c $< -o $@

deps:
	./scripts/make_cJSON_deps.sh
	./scripts/make_libwebsockets_deps.sh

clean:
	rm -rf $(BUILD_DIR)
	rm -rf lib/*
	rm -rf include/*
