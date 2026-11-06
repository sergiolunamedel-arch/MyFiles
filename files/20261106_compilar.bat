@echo off
setlocal EnableDelayedExpansion
REM Compila ScannerBase.exe (carpeta dist\ScannerBase). Requiere Python 3.12 o superior solo en la PC que compila.
REM Ejecutelo con doble clic como usuario normal (NO como administrador).
cd /d "%~dp0"

REM ── Python: prefiere 3.12 (la probada) y si no existe usa 3.13, 3.14 o el Python 3 disponible ──
set "PY="
for %%V in (3.12 3.13 3.14) do (
    if not defined PY (
        py -%%V -c "import sys" >nul 2>&1 && set "PY=py -%%V"
    )
)
if not defined PY (
    py -3 -c "import sys; sys.exit(0 if sys.version_info >= (3, 12) else 1)" >nul 2>&1 && set "PY=py -3"
)
if not defined PY (
    python -c "import sys; sys.exit(0 if sys.version_info >= (3, 12) else 1)" >nul 2>&1 && set "PY=python"
)
if not defined PY (
    echo No se encontro Python 3.12 o superior.
    echo Instalelo desde python.org marcando "py launcher", "Add python.exe to PATH" y "tcl/tk and IDLE".
    goto :err
)
for /f "delims=" %%I in ('%PY% -c "import sys; print(sys.version.split()[0])"') do set "PYVER=%%I"
echo Usando Python %PYVER%  (%PY%)
echo.

%PY% -c "import tkinter" >nul 2>&1 || (
    echo Esta instalacion de Python no incluye tcl/tk ^(tkinter^), necesario para la interfaz.
    echo Panel de control ^> Programas ^> Python %PYVER% ^> Modificar ^> marque "tcl/tk and IDLE".
    goto :err
)

REM ── El .exe abierto bloquea dist\ScannerBase: hay que cerrarlo antes de compilar ──
tasklist /fi "imagename eq ScannerBase.exe" 2>nul | find /i "ScannerBase.exe" >nul && (
    echo ScannerBase.exe esta abierto. Cierrelo y vuelva a ejecutar este script.
    goto :err
)

REM ── Carpeta de trabajo NUEVA en cada compilacion, fuera de Documentos/OneDrive ──
REM Antes se reutilizaba .\build y PyInstaller fallaba al borrarla cuando el antivirus/EDR o OneDrive tenian
REM bloqueado algun archivo (PermissionError: Acceso denegado ...\build\ScannerBase\localpycs).
set "WORKROOT=%LOCALAPPDATA%\ScannerBase_build"
set "WORK=%WORKROOT%\%RANDOM%%RANDOM%"
if not exist "%WORKROOT%" mkdir "%WORKROOT%"
REM Limpieza de compilaciones anteriores: lo que siga bloqueado simplemente se queda (ya no estorba).
for /d %%D in ("%WORKROOT%\*") do rmdir /s /q "%%D" >nul 2>&1
if exist build (
    attrib -r -s -h build\* /s /d >nul 2>&1
    rmdir /s /q build >nul 2>&1
)

REM ── dist\ScannerBase: se reintenta el borrado unos segundos por si el antivirus aun lo revisa ──
if exist dist\ScannerBase (
    attrib -r -s -h dist\ScannerBase\* /s /d >nul 2>&1
    for /l %%N in (1,1,5) do (
        if exist dist\ScannerBase (
            rmdir /s /q dist\ScannerBase >nul 2>&1
            if exist dist\ScannerBase timeout /t 2 /nobreak >nul
        )
    )
    if exist dist\ScannerBase (
        echo No se pudo borrar dist\ScannerBase: algun archivo sigue en uso ^(antivirus, OneDrive o una
        echo ventana del Explorador abierta en esa carpeta^). Cierrela, espere un minuto y reintente.
        goto :err
    )
)

%PY% -m pip install --upgrade pyinstaller jinja2 selenium webdriver-manager pynput pyyaml requests send2trash || goto :err
%PY% -m PyInstaller --noconfirm --clean --workpath "%WORK%" ScannerBase.spec || goto :err
rmdir /s /q "%WORK%" >nul 2>&1
REM Firma opcional con el certificado de firma de codigo de Banco Base (evita avisos de SmartScreen/antivirus):
REM signtool sign /fd SHA256 /tr http://timestamp.digicert.com /td SHA256 /n "Banco Base" dist\ScannerBase\ScannerBase.exe
echo.
echo Listo: dist\ScannerBase\ScannerBase.exe  (compilado con Python %PYVER%)
pause
exit /b 0

:err
echo Fallo la compilacion.
pause
exit /b 1