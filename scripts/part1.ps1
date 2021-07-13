Remove-Item -Path "c:\BGinfo" -Force -Recurse

New-Item -Path "c:\" -Name "WORK" -ItemType "directory"
cd c:\WORK

Invoke-WebRequest "https://github.com/go2tom42/win/raw/main/files/part1.zip" -OutFile "c:\WORK\part1.zip"
Expand-Archive -Path part1.zip -DestinationPath "c:\WORK"


Expand-Archive -Path skus-Windows-10.zip -DestinationPath $Env:windir\System32\spp\tokens\skus

start-process -FilePath "cmd.exe" -ArgumentList "/c cscript %windir%\system32\slmgr.vbs /rilc" -Wait -Passthru -NoNewWindow
start-process -FilePath "cmd.exe" -ArgumentList "/c cscript %windir%\system32\slmgr.vbs /upk >nul 2>&1" -Wait -Passthru -NoNewWindow
start-process -FilePath "cmd.exe" -ArgumentList "/c cscript %windir%\system32\slmgr.vbs /ckms >nul 2>&1" -Wait -Passthru -NoNewWindow
start-process -FilePath "cmd.exe" -ArgumentList "/c cscript %windir%\system32\slmgr.vbs /cpky >nul 2>&1" -Wait -Passthru -NoNewWindow
start-process -FilePath "cmd.exe" -ArgumentList "/c cscript %windir%\system32\slmgr.vbs /ipk NPPR9-FWDCX-D2C8J-H872K-2YT43" -Wait -Passthru -NoNewWindow
start-process -FilePath "cmd.exe" -ArgumentList "/c sc config LicenseManager start= auto & net start LicenseManager" -Wait -Passthru -NoNewWindow
start-process -FilePath "cmd.exe" -ArgumentList "/c sc config wuauserv start= auto & net start wuauserv" -Wait -Passthru -NoNewWindow
start-process -FilePath "cmd.exe" -ArgumentList "/c clipup -v -o -altto c:\" -Wait -Passthru -NoNewWindow
./dome.cmd /u

New-LocalUser "tom42" -NoPassword -FullName "tom42" -Description "tom42 local admin"
Add-LocalGroupMember -Group "Administrators" -Member "tom42"
Set-LocalUser -name "tom42" -Password ([securestring]::new())

Get-CimInstance -Class Win32_UserProfile | Where-Object { $_.LocalPath.split('\')[-1] -eq 'IEUSER' } | Remove-CimInstance
Remove-LocalUser -Name “IEUSER”
net user “IEUSER” /delete
Start-Sleep -s 5
Restart-Computer
