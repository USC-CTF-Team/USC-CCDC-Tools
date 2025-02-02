@echo off
setlocal enabledelayedexpansion

# Set the output directory to ./Reports
set "output_dir=.\Reports"

# Create the Reports directory if it doesn't exist
if not exist "%output_dir%" (
    mkdir "%output_dir%"
    echo Created directory: %output_dir%
)

echo ===============================================================================
echo Windows System Information Gathering Script
echo ===============================================================================
echo This script will collect various system information and save it as HTML files.
echo Output will be saved in %output_dir%
echo ===============================================================================
echo.

echo Script started at %date% %time%
echo.

# Function to run WMIC commands and log the output
:run_wmic
set "command=%~1"
set "output_file=%~2"
set "description=%~3"

echo Running: %description%
%command% > "%output_dir%\%output_file%"
if %errorlevel% equ 0 (
    echo [SUCCESS] %description% completed.
) else (
    echo [ERROR] %description% failed. Error code: %errorlevel%
)
echo.
goto :eof

# Run WMIC commands
call :run_wmic "wmic os get /format:htable" "os.html" "Operating System Information"
call :run_wmic "wmic qfe get /format:htable" "kbarticles.html" "Windows Patch Information"
call :run_wmic "wmic product get name, version, vendor /format:htable" "product.html" "Installed Software"
call :run_wmic "wmic process list brief /format:htable" "process.html" "Running Processes"
call :run_wmic "wmic service list full /format:htable" "services.html" "Services Information"
call :run_wmic "wmic startup list full /format:htable" "startup.html" "Startup Applications"
call :run_wmic "wmic useraccount list full /format:htable" "useraccount.html" "User Account Details"
call :run_wmic "wmic group list full /format:htable" "grouplist.html" "Group List Details"
call :run_wmic "wmic nic list full /format:htable" "nic.html" "Network Interface Information"

echo ===============================================================================
echo Script completed at %date% %time%
echo All output files have been saved in: %output_dir%
echo ===============================================================================

# Open all generated HTML files
echo Opening generated HTML files...
start "" "%output_dir%"

echo.
echo Press any key to exit...
pause >nul
