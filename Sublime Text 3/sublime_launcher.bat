rem @echo off
setlocal enableDelayedExpansion
set /a skip=0
set res=
for %%x in (%*) do (
    if "%%~x" == "-z" (
        set /a skip=1
    ) else (
        if "!skip!" neq "1" (
        	if "!res!" neq "" (
                set "res=!res! %%~x"
            ) else (
                set "res=%%~x"
            )
        )
        set /a skip=0
    )
    echo %%~x
    echo.!res!
    echo.!skip!
)
if "%res%" neq """" (
    "%~dp0sublime_text.exe" "%res%"
) else (
    "%~dp0sublime_text.exe"
)
endlocal