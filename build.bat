@echo off
REM CortexEDR Build Script
REM Run as Administrator

echo ========================================
echo CortexEDR Build Script
echo ========================================
echo.

REM Check if vcpkg path is set
if "%VCPKG_ROOT%"=="" (
    echo ERROR: VCPKG_ROOT environment variable not set
    echo Please set VCPKG_ROOT to your vcpkg installation directory
    echo Example: set VCPKG_ROOT=C:\vcpkg
    exit /b 1
)

echo Using vcpkg from: %VCPKG_ROOT%
echo.

REM Create build directory
if not exist build mkdir build

REM Configure CMake
echo Configuring CMake...
cmake -B build -S . -DCMAKE_TOOLCHAIN_FILE=%VCPKG_ROOT%\scripts\buildsystems\vcpkg.cmake
if errorlevel 1 (
    echo ERROR: CMake configuration failed
    exit /b 1
)

echo.
echo Building Release configuration...
cmake --build build --config Release
if errorlevel 1 (
    echo ERROR: Build failed
    exit /b 1
)

echo.
echo Running tests...
cd build
ctest -C Release --output-on-failure
cd ..

echo.
echo ========================================
echo Build complete!
echo Executable: build\Release\CortexEDR.exe
echo ========================================
echo.
echo To run CortexEDR:
echo   1. Open Command Prompt as Administrator
echo   2. Run: build\Release\CortexEDR.exe
echo.
