TEMPLATE = subdirs
SUBDIRS = sub_src sub_tools sub_unittest sub_examples

sub_src.subdir = src
sub_tools.subdir = tools
sub_tools.depends = sub_src
sub_unittest.subdir = unittest
sub_unittest.depends = sub_src
sub_examples.subdir = examples
sub_examples.depends = sub_src

include(conf.pri)

!isEmpty(QCA_NO_TESTS) {
	SUBDIRS -= sub_unittest sub_examples
}

unix: {
	# API documentation
	#apidox.commands += doxygen && cd apidocs/html && ./installdox -lqt.tag@/home/bradh/build/qt-x11-opensource-4.0.0-rc1-snapshot/doc/html/ && cd ../..
	apidox.commands += doxygen && cd apidocs/html && ./installdox -lqt.tag@http://doc.trolltech.com/4.1 && cd ../..
	QMAKE_EXTRA_TARGETS += apidox

	# unittest
	test.commands += cd unittest && make test && cd ..
	QMAKE_EXTRA_TARGETS += test
}
