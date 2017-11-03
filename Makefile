PROGRAM_NAME=archtorify
VERSION=1.10.1

LICENSE_DIR=/usr/share/licenses
DOCS_DIR=/usr/share/doc
PROGRAM_DIR=/usr/bin
CONFIG_DIR=/opt

install:
	install -Dm644 LICENSE $(LICENSE_DIR)/$(PROGRAM_NAME)/LICENSE
	install -Dm644 README.md $(DOCS_DIR)/$(PROGRAM_NAME)/README.md
	install -Dm755 archtorify.sh $(PROGRAM_DIR)/$(PROGRAM_NAME)
	mkdir -p $(CONFIG_DIR)/$(PROGRAM_NAME)/backups
	cp -R cfg $(CONFIG_DIR)/$(PROGRAM_NAME)

uninstall:
	rm -Rf $(LICENSE_DIR)/$(PROGRAM_NAME)
	rm -Rf $(DOCS_DIR)/$(PROGRAM_NAME)
	rm -Rf $(PROGRAM_DIR)/$(PROGRAM_NAME)
	rm -Rf $(CONFIG_DIR)/$(PROGRAM_NAME)
