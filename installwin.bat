@echo off
REM install qmake feature file pointing to the current directory

if not defined QTDIR goto err
copy crypto.prf "%QTDIR%\mkspecs\features"
echo Installed crypto.prf as a qmake feature.
goto end

:err
echo Error: QTDIR not set (example: set QTDIR=C:\Qt\4.2.3).
goto end

:end
