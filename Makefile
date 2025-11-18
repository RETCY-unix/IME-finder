CC = gcc
CFLAGS = -O2 -Wall -Wextra -std=c11
LDFLAGS = -lpci
TARGET = ime_analyzer
SRC_DIR = src
BUILD_DIR = build
INSTALL_DIR = /usr/local/bin

SOURCES = $(SRC_DIR)/main.c \
          $(SRC_DIR)/devices.c \
          $(SRC_DIR)/scanner_linux.c

OBJECTS = $(SOURCES:$(SRC_DIR)/%.c=$(BUILD_DIR)/%.o)

all: $(BUILD_DIR) $(TARGET)

$(BUILD_DIR):
	mkdir -p $(BUILD_DIR)

$(TARGET): $(OBJECTS)
	$(CC) $(OBJECTS) -o $(TARGET) $(LDFLAGS)
	@echo "Build complete: $(TARGET)"
	@echo "Run with: sudo ./$(TARGET)"

$(BUILD_DIR)/%.o: $(SRC_DIR)/%.c
	$(CC) $(CFLAGS) -c $< -o $@

clean:
	rm -rf $(BUILD_DIR) $(TARGET)
	@echo "Clean complete"

install: $(TARGET)
	install -m 755 $(TARGET) $(INSTALL_DIR)/
	@echo "Installed to $(INSTALL_DIR)/$(TARGET)"

uninstall:
	rm -f $(INSTALL_DIR)/$(TARGET)
	@echo "Uninstalled $(TARGET)"

.PHONY: all clean install uninstall
