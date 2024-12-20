# Makefile pour Targetmap
CC = gcc
CFLAGS = -Wall -Wextra
LDFLAGS = -pthread
TARGET = rmap
INSTALL_DIR = /usr/local/bin

all: $(TARGET)

$(TARGET): reconmap.c
	$(CC) $(CFLAGS) -o $(TARGET) reconmap.c $(LDFLAGS)
	# Définir le bit SUID pour permettre l'exécution avec privilèges root
	sudo chown root:root $(TARGET)
	sudo chmod u+s $(TARGET)

install: all
	sudo cp $(TARGET) $(INSTALL_DIR)/
	sudo chown root:root $(INSTALL_DIR)/$(TARGET)
	sudo chmod u+s $(INSTALL_DIR)/$(TARGET)

uninstall:
	sudo rm -f $(INSTALL_DIR)/$(TARGET)

clean:
	rm -f $(TARGET)