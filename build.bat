echo off
setlocal

set PROJECT_NAME=ime_analyzer
set SRC_DIR=src
set BUILD_DIR=build

if not exist %BUILD_DIR% mkdir %BUILD_DIR%

echo ===============================================================================
echo Building Intel ME Security Analyzer for Windows
echo ===============================================================================

cl /nologo /O2 /W4 /Fe:%PROJECT_NAME%.exe ^
   %SRC_DIR%\main.c ^
   %SRC_DIR%\devices.c ^
   %SRC_DIR%\scanner_windows.c ^
   /I. ^
   setupapi.lib cfgmgr32.lib

if %ERRORLEVEL% EQU 0 (
    echo.
    echo ===============================================================================
    echo Build successful!
    echo Executable: %PROJECT_NAME%.exe
    echo Run as Administrator for full functionality
    echo ===============================================================================
    move *.obj %BUILD_DIR%\ >nul 2>&1
) else (
    echo.
    echo ===============================================================================
    echo Build failed!
    echo ===============================================================================
)

endlocal
