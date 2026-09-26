@echo off
setlocal EnableExtensions DisableDelayedExpansion
cd /d "%~dp0"
title Sabores das Divas - Servidor na rede local

if not exist "server.py" (
    echo ERRO: server.py nao encontrado nesta pasta.
    echo Coloque INICIAR_REDE_LOCAL.bat na mesma pasta de server.py e INICIAR_WINDOWS.bat.
    pause
    exit /b 1
)
where python >nul 2>&1
if errorlevel 1 (
    echo ERRO: Python nao encontrado. Instale o Python e tente novamente.
    pause
    exit /b 1
)

echo ============================================================
echo  SABORES DAS DIVAS - ACESSO PELO CELULAR NA MESMA REDE
echo ============================================================
echo.
echo Procurando o endereco IPv4 do computador na rede local...

set "LAN_IP="
for /f "usebackq delims=" %%I in (`powershell.exe -NoProfile -NonInteractive -Command "foreach ($nic in (Get-NetIPConfiguration)) { if ($nic.IPv4DefaultGateway -and $nic.IPv4Address) { foreach ($addr in $nic.IPv4Address) { $ip=$addr.IPAddress; if (($ip.StartsWith('10.') -or $ip.StartsWith('192.168.') -or ($ip.StartsWith('172.') -and [int]($ip.Split('.')[1]) -ge 16 -and [int]($ip.Split('.')[1]) -le 31))) { Write-Output $ip; exit 0 } } } }"`) do if not defined LAN_IP set "LAN_IP=%%I"

if defined LAN_IP (
    echo Endereco encontrado: %LAN_IP%
    echo Pressione ENTER para usa-lo, ou digite outro IPv4 do computador.
) else (
    echo Nao foi possivel identificar o IPv4 automaticamente.
    echo Consulte o Endereco IPv4 de sua conexao Ethernet com: ipconfig
)
set "IP_ESCOLHIDO="
set /p "IP_ESCOLHIDO=IPv4 do computador [%LAN_IP%]: "
if defined IP_ESCOLHIDO set "LAN_IP=%IP_ESCOLHIDO%"
if not defined LAN_IP (
    echo ERRO: Informe o IPv4 local do computador.
    pause
    exit /b 1
)

rem Aceita somente um endereco IPv4 privado valido, sem comandos nem URLs.
powershell.exe -NoProfile -NonInteractive -Command "$ip=$null; if ($env:LAN_IP -notmatch '^([0-9]{1,3}[.]){3}[0-9]{1,3}$' -or -not [System.Net.IPAddress]::TryParse($env:LAN_IP, [ref]$ip) -or $ip.AddressFamily -ne [System.Net.Sockets.AddressFamily]::InterNetwork -or -not ($env:LAN_IP.StartsWith('10.') -or $env:LAN_IP.StartsWith('192.168.') -or ($env:LAN_IP.StartsWith('172.') -and [int]($env:LAN_IP.Split('.')[1]) -ge 16 -and [int]($env:LAN_IP.Split('.')[1]) -le 31))) { exit 1 }"
if errorlevel 1 (
    echo ERRO: O endereco informado deve ser um IPv4 privado valido desta rede.
    pause
    exit /b 1
)

set "SDD_HOST=0.0.0.0"
set "SDD_PORT=8080"
set "SDD_PUBLIC_ORIGIN=http://%LAN_IP%:%SDD_PORT%"
set "SDD_SECURE_COOKIE=0"

echo.
echo Preparando os cadastros existentes...
python server.py seed-clients
if errorlevel 1 goto :falha_configuracao

rem A senha so fica visivel no CMD caso seja necessario criar o primeiro administrador.
set "SDD_SHOW_BOOTSTRAP_PASSWORD=1"
python server.py bootstrap-admin
if errorlevel 1 goto :falha_configuracao
set "SDD_SHOW_BOOTSTRAP_PASSWORD="

echo.
echo ============================================================
echo  Acesse no CELULAR e no COMPUTADOR:
echo  %SDD_PUBLIC_ORIGIN%
echo ============================================================
echo  Deixe esta janela aberta enquanto utilizar o aplicativo.
echo  Celular e computador devem estar na mesma rede principal.
echo  Caso o acesso falhe, verifique o Firewall do Windows
echo  e autorize Python na rede PRIVADA; nao abra portas no roteador.
echo  ATENCAO: acesso via HTTP; use apenas em rede local confiavel.
echo.
python server.py serve
if errorlevel 1 goto :falha_servidor
exit /b 0

:falha_configuracao
set "SDD_SHOW_BOOTSTRAP_PASSWORD="
echo.
echo ERRO: configuracao interrompida. O servidor nao foi iniciado.
pause
exit /b 1

:falha_servidor
echo.
echo ERRO: o servidor nao iniciou. Confira se a porta 8080 ja esta em uso.
pause
exit /b 1
