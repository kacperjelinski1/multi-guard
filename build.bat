@echo off
REM === VeraxCore Antivirus build pipeline ============================
REM By Ali Sakkaf - https://alisakkaf.com
REM This batch file is for the USER to run manually. The agent never runs it.
setlocal

set QT_STATIC=C:\Qt\Static_5.14.2\5.14.2\bin
set MINGW=C:\Qt\Qt5.14.1\Tools\mingw730_32\bin
set PATH=%QT_STATIC%;%MINGW%;%PATH%

if exist Makefile mingw32-make distclean >nul 2>&1
if exist .obj  rmdir /s /q .obj  >nul 2>&1
if exist .moc  rmdir /s /q .moc  >nul 2>&1
if exist .qrc  rmdir /s /q .qrc  >nul 2>&1
if exist .ui   rmdir /s /q .ui   >nul 2>&1

echo [1/4] Generating translations...
if exist i18n\verax_pl.ts lrelease.exe i18n\verax_pl.ts -qm i18n\verax_pl.qm

echo [2/4] Running qmake...
qmake Verax.pro -spec win32-g++ "CONFIG+=release" || goto :error

echo [3/4] Compiling...
mingw32-make -j%NUMBER_OF_PROCESSORS% release || goto :error

echo [4/4] Stripping symbols...
if exist RELEASED\Multi-Guard.exe strip RELEASED\Multi-Guard.exe

echo.
echo =================================================
echo  BUILD OK : RELEASED\Multi-Guard.exe (Multi-Guard)
echo =================================================
goto :eof

:error
echo BUILD FAILED - check output above.
exit /b 1
