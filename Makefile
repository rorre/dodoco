BIN := dodoco
CERT_DIR := certs
CA_CERT := $(CERT_DIR)/ca.crt
CA_KEY := $(CERT_DIR)/ca.key
INSTALL_DIR := $(HOME)/.local/bin
CONFIG_DIR := $(HOME)/.config/dodoco
UNIT_DIR := $(HOME)/.config/systemd/user

define UNIT_FILE
[Unit]
Description=Dodoco Proxy
After=network-online.target
Wants=network-online.target

[Service]
ExecStart=$(INSTALL_DIR)/$(BIN)
Restart=on-failure
RestartSec=5

[Install]
WantedBy=default.target
endef
export UNIT_FILE


.PHONY: build
build:
	mkdir dist
	go build -o dist/$(BIN) ./cmd/dodoco
	sudo setcap cap_net_raw=+ep $(BIN)

.PHONY: run
run: build
	./$(BIN)

.PHONY: install
install: build
	install -Dm755 $(BIN) $(INSTALL_DIR)/$(BIN)
	sudo setcap cap_net_raw=+ep $(INSTALL_DIR)/$(BIN)
	mkdir -p $(CONFIG_DIR)
	test -f $(CONFIG_DIR)/config.json || install -Dm644 config.json $(CONFIG_DIR)/config.json
	mkdir -p $(UNIT_DIR)
	echo "$$UNIT_FILE" > $(UNIT_DIR)/$(BIN).service
	systemctl --user daemon-reload
	@echo "Installed. Enable with: systemctl --user enable --now $(BIN)"

.PHONY: uninstall
uninstall:
	systemctl --user disable --now $(BIN) || true
	rm -f $(INSTALL_DIR)/$(BIN)
	rm -rf $(CONFIG_DIR)
	rm -f $(UNIT_DIR)/$(BIN).service
	systemctl --user daemon-reload

.PHONY: clean
clean:
	rm -f $(BIN)
