@echo off
setlocal
cd /d "%~dp0"

rem Safety: the database holds private data, so it is only pushed while the GitHub repo is private.
rem A private repo answers 404 to an anonymous request; anything else (200 = public, 000 = offline) stops here.
set CODE=
for /f %%c in ('curl -s -o nul -w "%%{http_code}" https://api.github.com/repos/subhi5/task_system') do set CODE=%%c
if not "%CODE%"=="404" (
    echo The GitHub repo is not private ^(answer %CODE%^) - the database was NOT uploaded.
    echo Make it private on github.com: Settings - Danger Zone - Change visibility.
    pause
    exit /b 1
)

git add db
git diff --cached --quiet -- db
if not errorlevel 1 (
    echo No data changes to save.
    pause
    exit /b 0
)
git commit -m "Data backup %date% %time%" -- db
git push origin main
pause
