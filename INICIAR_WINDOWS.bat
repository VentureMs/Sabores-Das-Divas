@echo off
cd /d "%~dp0"
where python >nul 2>&1
if errorlevel 1 (
  echo Python nao encontrado. Instale Python 3.11+ antes de continuar.
  pause
  exit /b 1
)
echo ===================================================
echo SABORES DAS DIVAS - PRIMEIRO ACESSO / TESTE LOCAL
echo ===================================================
python server.py seed-clients
if errorlevel 1 goto :falha_configuracao

rem Mostra a senha apenas na criacao inicial do administrador neste CMD.
set "SDD_SHOW_BOOTSTRAP_PASSWORD=1"
python server.py bootstrap-admin
set "SDD_SHOW_BOOTSTRAP_PASSWORD="
if errorlevel 1 goto :falha_configuracao

echo.
echo Abra http://127.0.0.1:8080 no navegador deste computador.
echo Esta janela precisa permanecer aberta durante o uso LOCAL.
echo Para acesso pela internet, leia LEIA_PRIMEIRO.md.
echo.
start "" "http://127.0.0.1:8080"
python server.py serve
if errorlevel 1 goto :falha_servidor
pause
exit /b 0

:falha_configuracao
set "SDD_SHOW_BOOTSTRAP_PASSWORD="
echo.
echo Configuracao interrompida. O programa NAO sera iniciado.
echo Confira a mensagem acima e execute INICIAR_WINDOWS.bat novamente.
pause
exit /b 1

:falha_servidor
echo.
echo Falha ao iniciar o servidor. Confira a mensagem acima.
pause
exit /b 1
