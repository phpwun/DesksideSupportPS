Dism.exe /online /import-defaultappassociations:%~dp0Dependencies\CustomFileAssoc.xml
powercgf /import %~dp0Dependencies\scheme.pow
powershell -ep Bypass %~dp0Dependencies\Main.ps1
pause
