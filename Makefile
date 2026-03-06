.POSIX:
.PHONY: install uninstall

install:
	cargo build --release
	cp target/release/nass "${DESTDIR}${PREFIX}/bin/pass"
	cp target/release/nass "${DESTDIR}${PREFIX}/bin/hiq"
	cp target/release/nass "${DESTDIR}${PREFIX}/bin/himitsud"

uninstall:
	rm -f "${DESTDIR}${PREFIX}/bin/pass" \
	rm -f "${DESTDIR}${PREFIX}/bin/hiq" \
	rm -f "${DESTDIR}${PREFIX}/bin/himitsud"
