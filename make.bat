@echo off
setlocal enabledelayedexpansion

if "%1"=="test" goto test
if "%1"=="demo" goto demo
if "%1"=="clean" goto clean
if "%1"=="" goto help

:test
echo Running all regression test suites...
python -m pytest tests/ -v
goto end

:demo
echo Running automated end-to-end regression demonstration...
python demo.py
goto end

:clean
echo Cleaning test artifacts and caches...
if exist .pytest_cache rd /s /q .pytest_cache
if exist backend_inventory.sqlite del /q backend_inventory.sqlite
if exist tickets.json del /q tickets.json
echo Clean complete.
goto end

:help
echo Usage: make.bat [test ^| demo ^| clean]
goto end

:end
