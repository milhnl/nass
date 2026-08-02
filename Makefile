.POSIX:
.PHONY: build install install-exe install-service-launchd \
	install-service-openrc install-service-systemd uninstall

#Portably detect launchd, systemd or openrc (if pid 1 is called init)
init != ps -Aopid=,comm= | sed -En 's/init/openrc/;s/^ *1 (.*\/)?//p'
init ?= $(shell ${init !})
init := ${init}

build:
	cargo build --quiet --release

install: install-exe install-service-${init}

install-exe: build
	cp target/release/pass "${DESTDIR}${PREFIX}/bin/pass"; \
	cp target/release/hiq "${DESTDIR}${PREFIX}/bin/hiq"; \
	cp target/release/nassd "${DESTDIR}${PREFIX}/bin/nassd"; \

#macOS users probably expect it to be started and enabled on install
#Doing otherwise is more brittle code, and extra work for the user
install-service-launchd:
	set -eu; \
	domain="gui/$$(id -u)"; \
	service="$$domain/nl.milh.nassd"; \
	mkdir -p "$$HOME/Library/LaunchAgents"; \
	<service/nl.milh.nassd.plist \
		sed 's|$$EXE|${PREFIX}/bin/nassd|' \
	>"$$HOME/Library/LaunchAgents/nl.milh.nassd.plist"; \
	if ! launchctl print "$$service" >/dev/null 2>&1; then \
		launchctl bootstrap "$$domain" \
			"$$HOME/Library/LaunchAgents/nl.milh.nassd.plist"; \
		printf 'Background service for nassd started\n' >&2; \
	else \
		printf 'Restart service with:\n' >&2; \
		printf 'launchctl bootout "%s"\n' "$$service" >&2; \
		printf 'launchctl kickstart -k "%s"\n' "$$service" >&2; \
	fi; \

#I expect openrc users to figure out enable/start themselves
install-service-openrc:
	set -eu; \
	XDG_CONFIG_HOME="$${XDG_CONFIG_HOME:-$$HOME/.config}"; \
	mkdir -p "$$XDG_CONFIG_HOME/rc/init.d"; \
	<service/nassd \
		sed 's|$$EXE|${PREFIX}/bin/nassd|' \
	>"$$XDG_CONFIG_HOME/rc/init.d/nassd"; \
	chmod +x "$$XDG_CONFIG_HOME/rc/init.d/nassd"; \
	printf 'Enable/start OpenRC service `nassd` to continue\n' >&2; \

install-service-systemd:
	set -eu; \
	XDG_DATA_HOME="$${XDG_DATA_HOME:-$$HOME/.local/share}"; \
	mkdir -p "$$XDG_DATA_HOME/systemd/user"; \
	<service/nassd.service \
		sed 's|$$EXE|${PREFIX}/bin/nassd|' \
	>"$$XDG_DATA_HOME/systemd/user/nassd.service"; \
	systemctl --user daemon-reload; \
	printf 'Enable and (re)start service with:\n' >&2; \
	printf 'systemctl --user enable nassd.service\n' >&2; \
	printf 'systemctl --user restart nassd.service\n' >&2; \

uninstall:
	rm -f "${DESTDIR}${PREFIX}/bin/pass"; \
	rm -f "${DESTDIR}${PREFIX}/bin/hiq"; \
	rm -f "${DESTDIR}${PREFIX}/bin/nassd"; \
	XDG_CONFIG_HOME="$${XDG_CONFIG_HOME:-$$HOME/.config}"; \
	XDG_DATA_HOME="$${XDG_DATA_HOME:-$$HOME/.local/share}"; \
	rm -f "$$HOME/Library/LaunchAgents/nl.milh.nassd.plist"; \
	rm -f "$$XDG_CONFIG_HOME/rc/init.d/nassd"; \
	rm -f "$$XDG_DATA_HOME/systemd/user/nassd.service"; \
