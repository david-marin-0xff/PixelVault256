@echo off
echo =====================================
echo Building PixelVault256 (Windows)
echo =====================================

REM Activate virtual environment
call .venv\Scripts\activate

REM Clean old builds
rmdir /s /q build dist
del /q pixelvault256.spec 2>nul

REM Build executable
pyinstaller --onefile --windowed --icon=logo.png pixelvault256.py

echo.
echo Build complete! Your EXE is in the "dist" folder.
pause
