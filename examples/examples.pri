include(../confapp.pri)

# default to console (individual programs can always override this if needed)
CONFIG += console
CONFIG -= app_bundle
QT -= gui

# In a real application, you use the install locations
# (eg /usr/local/include/QtCrypto and /usr/local/lib). We just do this
# so you can see the examples without needing to install first.
INCLUDEPATH += ../../include/QtCrypto
LIBS += -L../../lib

# link
LIBS += -l$$QCA_LIBNAME
