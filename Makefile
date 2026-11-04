BIN_DIR    := bin
TARGET_DIR := target/release

CLIENT  := $(BIN_DIR)/fwknop
SERVER  := $(BIN_DIR)/fwknopd
CONVERT := $(BIN_DIR)/fwknop-convert

CARGO      ?= cargo
CARGOFLAGS ?=

# Install locations (override on the command line, e.g. make install-systemd PREFIX=/usr)
PREFIX     ?= /usr/local
SYSCONFDIR ?= /etc/fwknop
UNITDIR    ?= /etc/systemd/system
INSTALL    ?= install

# Go <-> Rust interop: where to find fwknop-go and which branch to build.
FWKNOP_GO_DIR ?= ../fwknop-go
FWKNOP_GO_REF ?= mlbright/main
INTEROP_DIR   := target/interop

.PHONY: all client server convert clean test lint fmt install interop firewall-test \
	install-systemd uninstall-systemd help

all: client server convert  ## Build all binaries into bin/

client:  ## Build the fwknop client
	$(CARGO) build --release $(CARGOFLAGS) -p fwknop-cli
	@mkdir -p $(BIN_DIR)
	cp $(TARGET_DIR)/fwknop $(CLIENT)

server:  ## Build the fwknopd server
	$(CARGO) build --release $(CARGOFLAGS) -p fwknopd
	@mkdir -p $(BIN_DIR)
	cp $(TARGET_DIR)/fwknopd $(SERVER)

convert:  ## Build the fwknop-convert utility
	$(CARGO) build --release $(CARGOFLAGS) -p fwknop-convert
	@mkdir -p $(BIN_DIR)
	cp $(TARGET_DIR)/fwknop-convert $(CONVERT)

install:  ## Install binaries to ~/.cargo/bin
	$(CARGO) install $(CARGOFLAGS) --path crates/fwknop-cli
	$(CARGO) install $(CARGOFLAGS) --path crates/fwknopd
	$(CARGO) install $(CARGOFLAGS) --path crates/fwknop-convert

install-systemd: server  ## Install fwknopd binary, systemd unit, and sample configs
	$(INSTALL) -d $(DESTDIR)$(PREFIX)/bin
	$(INSTALL) -m 0755 $(SERVER) $(DESTDIR)$(PREFIX)/bin/fwknopd
	$(INSTALL) -d $(DESTDIR)$(SYSCONFDIR)/actions
	$(INSTALL) -m 0644 conf_files/server.yaml $(DESTDIR)$(SYSCONFDIR)/server.yaml.sample
	$(INSTALL) -m 0600 conf_files/access.yaml $(DESTDIR)$(SYSCONFDIR)/access.yaml.sample
	$(INSTALL) -m 0644 conf_files/actions/*.yaml $(DESTDIR)$(SYSCONFDIR)/actions/
	$(INSTALL) -d $(DESTDIR)$(UNITDIR)
	$(INSTALL) -m 0644 systemd/fwknopd.service $(DESTDIR)$(UNITDIR)/fwknopd.service
	@echo
	@echo "Installed fwknopd and the systemd unit."
	@echo "Next steps:"
	@echo "  1. cp $(SYSCONFDIR)/server.yaml.sample $(SYSCONFDIR)/server.yaml   # and edit"
	@echo "  2. cp $(SYSCONFDIR)/access.yaml.sample $(SYSCONFDIR)/access.yaml   # add your keys"
	@echo "  3. systemctl daemon-reload"
	@echo "  4. systemctl enable --now fwknopd"

uninstall-systemd:  ## Stop and remove the fwknopd systemd unit and binary
	-systemctl disable --now fwknopd 2>/dev/null || true
	rm -f $(DESTDIR)$(UNITDIR)/fwknopd.service
	rm -f $(DESTDIR)$(PREFIX)/bin/fwknopd
	-systemctl daemon-reload 2>/dev/null || true
	@echo "Removed fwknopd unit and binary. Config under $(SYSCONFDIR) was left in place."

test:  ## Run all tests (the Go interop tests are skipped; see `make interop`)
	$(CARGO) test --workspace $(CARGOFLAGS)

interop:  ## Build fwknop-go from FWKNOP_GO_DIR at FWKNOP_GO_REF and run the Go <-> Rust tests
	@test -d $(FWKNOP_GO_DIR)/.git || { echo "fwknop-go checkout not found at $(FWKNOP_GO_DIR) (set FWKNOP_GO_DIR)"; exit 1; }
	rm -rf $(INTEROP_DIR)/go-src
	mkdir -p $(INTEROP_DIR)/go-src $(INTEROP_DIR)/bin
	git -C $(FWKNOP_GO_DIR) archive $(FWKNOP_GO_REF) | tar -x -C $(INTEROP_DIR)/go-src
	cd $(INTEROP_DIR)/go-src && go build -o ../bin/ ./cmd/fwknop ./cmd/fwknopd ./cmd/fwknop-convert
	$(CARGO) build --workspace $(CARGOFLAGS)
	FWKNOP_GO_BIN_DIR=$(abspath $(INTEROP_DIR)/bin) FWKNOP_RS_BIN_DIR=$(abspath target/debug) \
		$(CARGO) test -p interop-tests $(CARGOFLAGS) -- --nocapture

firewall-test:  ## Test the nftables and iptables templates on the kernel firewall (Linux, sudo)
	$(CARGO) build $(CARGOFLAGS) -p fwknop-cli -p fwknopd
	sudo test/firewall/run.sh target/debug

lint:  ## Run clippy with warnings as errors
	$(CARGO) clippy --workspace --all-targets $(CARGOFLAGS) -- -D warnings

fmt:  ## Format all Rust code
	$(CARGO) fmt --all

clean:  ## Remove build artifacts
	$(CARGO) clean
	rm -rf $(BIN_DIR)

help:  ## Show this help
	@grep -E '^[a-zA-Z_-]+:.*?## .*$$' $(MAKEFILE_LIST) | \
		awk 'BEGIN {FS = ":.*?## "}; {printf "  %-18s %s\n", $$1, $$2}'
