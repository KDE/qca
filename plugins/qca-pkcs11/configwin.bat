@echo off
REM write conf_win.pri

if "%1"=="rd" goto debug_and_release
if "%1"=="r" goto release
if "%1"=="d" goto debug
if "%1"=="rds" goto debug_and_release_static
if "%1"=="rs" goto release_static
if "%1"=="ds" goto debug_static
goto usage

:usage
echo usage: configwin [mode]
echo modes:
echo   rd          release and debug, dynamic
echo   r           release, dynamic
echo   d           debug, dynamic
echo   rds         release and debug, static
echo   rs          release static
echo   ds          debug static
goto end

:debug_and_release
echo Configuring for release and debug, dynamic
echo CONFIG += debug_and_release build_all > conf_win.pri
goto done

:release
echo Configuring for release, dynamic
echo CONFIG += release > conf_win.pri
goto done

:debug
echo Configuring for debug, dynamic
echo CONFIG += debug > conf_win.pri
goto done

:debug_and_release_static
echo Configuring for release and debug, static
echo CONFIG += debug_and_release build_all staticlib > conf_win.pri
goto done

:release_static
echo Configuring for release, static
echo CONFIG += release staticlib > conf_win.pri
goto done

:debug_static
echo Configuring for debug, static
echo CONFIG += debug staticlib > conf_win.pri
goto done

:done
echo Wrote conf_win.pri

:end
