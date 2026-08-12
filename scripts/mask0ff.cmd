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
setlocal EnableDelayedExpansion
rem CMDCMDLINE holds the command line of the cmd.exe that is running this file,
rem before cmd.exe reinterpreted anything. Delayed expansion inserts it after the
rem line has already been parsed, so the value arrives exact. Everything the
rem router needs in order to tell what was typed from what survived is in here.
set "MASK0FF_RAW_CMDLINE=!CMDCMDLINE!"
set "MASK0FF_MANGLE_MARKER=%TEMP%\mask0ff-mangled-%RANDOM%%RANDOM%%RANDOM%.flag"
if exist "!MASK0FF_MANGLE_MARKER!" del /q "!MASK0FF_MANGLE_MARKER!" >nul 2>&1
rem The canary. It sits after %* on the line below, so it is the last argument the
rem router should see, on its own. If cmd.exe cut the line short, or disagreed with
rem the C runtime about where a quoted word ends, the canary is swallowed into the
rem argument before it instead of arriving whole. The router checks for that. This
rem catches a pipe, which CMDCMDLINE above does not see, because cmd.exe gives each
rem side of a pipe its own process and its own shortened command line.
set "MASK0FF_WRAPPER_TOKEN=%RANDOM%%RANDOM%%RANDOM%%RANDOM%"
set "PYTHONUTF8=1"
set "PYTHONIOENCODING=utf-8"
set "PYTHONDONTWRITEBYTECODE=1"
"%PYEXE%" %PYPREFIX% "%~dp0mask0ff.py" %* --mask0ff-wrapper-end=%MASK0FF_WRAPPER_TOKEN%
set "MASK0FF_RC=!ERRORLEVEL!"
rem The router writes the marker only when it proved the command line was split or
rem rewritten by cmd.exe. In that state cmd.exe is still holding the rest of the
rem line, ready to run it on this machine and to overwrite the exit code with its
rem own. A plain "exit /b" would let both happen. "exit" without /b ends the whole
rem cmd.exe process, so the queued text never runs and this code is the one the
rem caller sees.
if exist "!MASK0FF_MANGLE_MARKER!" (
  del /q "!MASK0FF_MANGLE_MARKER!" >nul 2>&1
  endlocal & exit 126
)
exit /b !MASK0FF_RC!
