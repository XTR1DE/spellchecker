@echo off
setlocal
cd /d "%~dp0"

echo Building services...
if not exist target mkdir target

go build -o target\proxy.exe static+proxy.go
if errorlevel 1 goto build_error

go build -o target\classifier.exe classifier.go
if errorlevel 1 goto build_error

echo Build successful.

start "Proxy :8080" target\proxy.exe
start "Classifier :8090" target\classifier.exe

echo Services started successfully.
timeout /t 3 /nobreak >nul
exit /b 0

:build_error
echo Build failed. Check the errors above.
pause
exit /b 1