echo off
setlocal

set PROJECT_NAME=ime_analyzer
set SRC_DIR=src
set BUILD_DIR=build

if not exist %BUILD_DIR% mkdir %BUILD_DIR%

echo ===============================================================================
echo Building Intel ME Security Analyzer for Windows (MinGW)
echo ===============================================================================
echo.

where gcc >nul 2>&1
if %ERRORLEVEL% NEQ 0 (
    echo ERROR: GCC compiler not found!
    echo.
    echo Install MinGW-w64 or use build.bat with Visual Studio
    goto :error
)

gcc -O2 -Wall -Wextra -o %PROJECT_NAME%.exe ^
    %SRC_DIR%\main.c ^
    %SRC_DIR%\devices.c ^
    %SRC_DIR%\win_scanner.c ^
    -lsetupapi -lcfgmgr32 -lole32 -luuid

if %ERRORLEVEL% EQU 0 (
    echo.
    echo ===============================================================================
    echo Build successful!
    echo Executable: %PROJECT_NAME%.exe
    echo Run as Administrator for full functionality
    echo ===============================================================================
    del *.o 2>nul
) else (
    echo.
    echo ===============================================================================
    echo Build failed!
    echo ===============================================================================
    goto :error
)

goto :end

:error
pause
exit /b 1

:end
endlocal
