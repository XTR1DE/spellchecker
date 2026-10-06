@echo off
chcp 65001 > nul

echo Билдим сервисы...
go build -o target\proxy.exe static+proxy.go
if %errorlevel% neq 0 (
    echo Ошибка сборки proxy.exe!
    pause
    exit /b
)

go build -o target\classifier.exe classifier.go
if %errorlevel% neq 0 (
    echo Ошибка сборки classifier.exe!
    pause
    exit /b
)

echo Все успешно скомпилировано в папку target!

start "Прокси-сервер :8080" target\proxy.exe
start "Классификатор :8090" target\classifier.exe


echo Все сервисы успешно запущены!
echo Это окно закроется автоматически через
timeout /t 1 /nobreak > nul
echo 3
timeout /t 1 /nobreak > nul
echo 2
timeout /t 1 /nobreak > nul
echo 1
timeout /t 1 /nobreak > nul
exit