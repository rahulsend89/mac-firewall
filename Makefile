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
	@echo '<plist version="1.0">' >> $@
	@echo '<dict>' >> $@
	@echo '    <key>com.apple.developer.endpoint-security.client</key>' >> $@
	@echo '    <true/>' >> $@
	@echo '</dict>' >> $@
	@echo '</plist>' >> $@

# Code sign with entitlements
sign: $(TARGET) $(ENTITLEMENTS)
	@echo "Code signing with entitlements..."
	codesign --force --sign - --entitlements $(ENTITLEMENTS) --deep $(TARGET)
	@echo "✓ Code signed successfully"

# Install (requires root)
install: sign
	@echo "Installing mac-firewall..."
	@if [ "$$(id -u)" != "0" ]; then \
		echo "Error: Installation requires root privileges"; \
		echo "Run: sudo make install"; \
		exit 1; \
	fi
	cp $(TARGET) /usr/local/bin/
	cp firewall.json /etc/mac-firewall.json
	chmod 755 /usr/local/bin/mac-firewall
	chmod 644 /etc/mac-firewall.json
	@echo "✓ Installed to /usr/local/bin/mac-firewall"
	@echo "✓ Config installed to /etc/mac-firewall.json"
	@echo ""
	@echo "To start the firewall:"
	@echo "  sudo mac-firewall"

# Uninstall
uninstall:
	@echo "Uninstalling mac-firewall..."
	@if [ "$$(id -u)" != "0" ]; then \
		echo "Error: Uninstallation requires root privileges"; \
		echo "Run: sudo make uninstall"; \
		exit 1; \
	fi
	rm -f /usr/local/bin/mac-firewall
	rm -f /etc/mac-firewall.json
	@echo "✓ Uninstalled"

# Clean build artifacts
clean:
	rm -rf $(BUILD_DIR) $(BIN_DIR)
	rm -f $(ENTITLEMENTS)
	@echo "✓ Cleaned build artifacts"

# Development: build and run (requires SIP disabled)
dev: sign
	@echo "Starting firewall in development mode..."