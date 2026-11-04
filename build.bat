@echo off
rem Build CertChainTool with MSVC (Visual Studio 2022 / Build Tools)
rem   build.bat          build the GUI app  -> build\CertChainTool.exe
rem   build.bat test     build and run the self test (needs tests\testdata, see tests\make_testdata.sh)
setlocal
cd /d "%~dp0"

where cl >nul 2>nul
if not errorlevel 1 goto havecl
set "VSWHERE=%ProgramFiles(x86)%\Microsoft Visual Studio\Installer\vswhere.exe"
for /f "usebackq tokens=*" %%i in (`"%VSWHERE%" -latest -products * -requires Microsoft.VisualStudio.Component.VC.Tools.x86.x64 -property installationPath`) do set "VSDIR=%%i"
if defined VSDIR call "%VSDIR%\VC\Auxiliary\Build\vcvars64.bat" >nul 2>nul
:havecl
where cl >nul 2>nul
if errorlevel 1 (
  echo [ERROR] MSVC compiler not found. Install Visual Studio 2022 Build Tools with "Desktop development with C++".
  exit /b 1
)

if not exist build mkdir build
set CFLAGS=/nologo /utf-8 /std:c++17 /EHsc /O2 /MT /W4 /permissive- /DUNICODE /D_UNICODE /DWIN32_LEAN_AND_MEAN /DNOMINMAX

if /i "%1"=="test" goto test

rc /nologo /fo build\app.res src\app.rc || exit /b 1
cl %CFLAGS% src\main.cpp src\certcore.cpp build\app.res /Fo:build\ /Fe:build\CertChainTool.exe ^
   /link /SUBSYSTEM:WINDOWS /MANIFEST:NO user32.lib gdi32.lib comctl32.lib comdlg32.lib shell32.lib cryptui.lib uxtheme.lib || exit /b 1
echo.
echo Built: build\CertChainTool.exe
exit /b 0

:test
if not exist build\test mkdir build\test
cl %CFLAGS% tests\selftest.cpp src\certcore.cpp /Fo:build\test\ /Fe:build\selftest.exe /link /SUBSYSTEM:CONSOLE || exit /b 1
if "%2"=="" (
  build\selftest.exe tests\testdata build\test\out
) else (
  build\selftest.exe "%2" build\test\out
)
exit /b %errorlevel%
