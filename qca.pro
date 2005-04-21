TEMPLATE = subdirs
SUBDIRS = src tools

include(conf.pri)

# install
pcfiles.path = $$PREFIX/lib/pkgconfig
pcfiles.files = qca.pc
INSTALLS += pcfiles

