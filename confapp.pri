unix:include(confapp_unix.pri)
windows:include(confapp_win.pri)

exists(crypto.prf) {
	# our apps should build against the qca in this tree
	include(crypto.prf)
} else {
	# attempt to use system-wide qca
	CONFIG *= crypto
}
