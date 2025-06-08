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

OBJECTS = $(SOURCES:$(SRC_DIR)/%.c=$(BUILD_DIR)/%.o)

# Targets
TARGET = $(BIN_DIR)/mac-firewall
ENTITLEMENTS = entitlements.plist

.PHONY: all clean install uninstall sign

all: $(TARGET)

# Create directories
$(BUILD_DIR):
	mkdir -p $(BUILD_DIR)

$(BIN_DIR):
	mkdir -p $(BIN_DIR)

# Compile cJSON library
$(BUILD_DIR)/cJSON.o: lib/cJSON.c lib/cJSON.h | $(BUILD_DIR)
	$(CC) $(CFLAGS) -c $< -o $@

# Compile source files
$(BUILD_DIR)/%.o: $(SRC_DIR)/%.c | $(BUILD_DIR)
	$(CC) $(CFLAGS) -c $< -o $@

# Link executable
$(TARGET): $(OBJECTS) $(BUILD_DIR)/cJSON.o | $(BIN_DIR)
	$(CC) $(CFLAGS) $^ $(FRAMEWORKS) $(LIBS) -o $@
	@echo "✓ Built $(TARGET)"

# Create entitlements file
$(ENTITLEMENTS):
	@echo "Creating entitlements file..."
	@echo '<?xml version="1.0" encoding="UTF-8"?>' > $@
	@echo '<!DOCTYPE plist PUBLIC "-//Apple//DTD PLIST 1.0//EN" "http://www.apple.com/DTDs/PropertyList-1.0.dtd">' >> $@