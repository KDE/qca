@echo off
REM install qmake feature file pointing to the current directory

echo QCA_INCDIR = %CD%\include > crypto.prf
echo QCA_LIBDIR = %CD%\lib >> crypto.prf
type crypto.prf.in >> crypto.prf
copy crypto.prf %QTDIR%\mkspecs\features

echo Installed crypto.prf as a qmake feature.
