# macOS Firewall Makefile

CC = clang

# Get macOS SDK path dynamically (fixes EndpointSecurity linking)
SDK_PATH := $(shell xcrun --sdk macosx --show-sdk-path 2>/dev/null)

# Compiler flags with SDK path
CFLAGS = -Wall -Wextra -O2 -fmodules -I./lib
ifneq ($(SDK_PATH),)
    CFLAGS += -isysroot $(SDK_PATH)
endif

# EndpointSecurity is a library, not a framework!
FRAMEWORKS = -framework Foundation -framework AppKit
LIBS = -lEndpointSecurity -lbsm

SRC_DIR = src
BUILD_DIR = build
BIN_DIR = bin

# Source files
SOURCES = $(SRC_DIR)/firewall_daemon.c \
          $(SRC_DIR)/config_parser.c \
          $(SRC_DIR)/process_tracker.c \
          $(SRC_DIR)/logger.c \
          $(SRC_DIR)/policy_engine.c