@echo off
setlocal
set "PYEXE="
set "PYPREFIX="

if defined MASK0FF_PYTHON (
  "%MASK0FF_PYTHON%" -c "import sys; raise SystemExit(0 if sys.version_info >= (3, 10) else 1)" >nul 2>&1
  if not errorlevel 1 (
    set "PYEXE=%MASK0FF_PYTHON%"
    goto found_python
  )
)

python3 -c "import sys; raise SystemExit(0 if sys.version_info >= (3, 10) else 1)" >nul 2>&1
if not errorlevel 1 (
  set "PYEXE=python3"
  goto found_python
)

python -c "import sys; raise SystemExit(0 if sys.version_info >= (3, 10) else 1)" >nul 2>&1
if not errorlevel 1 (
  set "PYEXE=python"
  goto found_python
)

py -3 -c "import sys; raise SystemExit(0 if sys.version_info >= (3, 10) else 1)" >nul 2>&1
if not errorlevel 1 (
  set "PYEXE=py"
  set "PYPREFIX=-3"
  goto found_python
)

set "BUNDLED_PYTHON=%USERPROFILE%\.cache\codex-runtimes\codex-primary-runtime\dependencies\python\python.exe"
if exist "%BUNDLED_PYTHON%" (
  "%BUNDLED_PYTHON%" -c "import sys; raise SystemExit(0 if sys.version_info >= (3, 10) else 1)" >nul 2>&1
  if not errorlevel 1 (
    set "PYEXE=%BUNDLED_PYTHON%"
    goto found_python
  )
)

>&2 echo ERROR: mask0ff requires Python 3.10 or newer. Set MASK0FF_PYTHON to a usable interpreter.
exit /b 2

:found_python
set "PYTHONUTF8=1"
set "PYTHONIOENCODING=utf-8"
set "PYTHONDONTWRITEBYTECODE=1"
"%PYEXE%" %PYPREFIX% "%~dp0mask0ff.py" %*
exit /b %ERRORLEVEL%
