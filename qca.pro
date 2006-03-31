TEMPLATE = subdirs
SUBDIRS = src tools unittest examples

unix:{
	include(conf.pri)

	# install
	pcfiles.path = $$PREFIX/lib/pkgconfig
	pcfiles.files = qca.pc
	INSTALLS += pcfiles

	# API documentation
	#apidox.commands += doxygen && cd apidocs/html && ./installdox -lqt.tag@/home/bradh/build/qt-x11-opensource-4.0.0-rc1-snapshot/doc/html/ && cd ../..
	apidox.commands += doxygen && cd apidocs/html && ./installdox -lqt.tag@http://doc.trolltech.com/4.1 && cd ../..
	QMAKE_EXTRA_TARGETS += apidox

	# unittest
	check.commands += cd unittest && make check && cd ..
	QMAKE_EXTRA_TARGETS += check
}
