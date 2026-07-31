.POSIX:
.PHONY: install uninstall

install:
	cargo build --release
	cp target/release/pass "${DESTDIR}${PREFIX}/bin/pass"
	cp target/release/hiq "${DESTDIR}${PREFIX}/bin/hiq"
	cp target/release/nassd "${DESTDIR}${PREFIX}/bin/nassd"

uninstall:
	rm -f "${DESTDIR}${PREFIX}/bin/pass" \
	rm -f "${DESTDIR}${PREFIX}/bin/hiq" \
	rm -f "${DESTDIR}${PREFIX}/bin/nassd"
