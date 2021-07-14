
Get-CimInstance -Class Win32_UserProfile | Where-Object { $_.LocalPath.split('\')[-1] -eq 'IEUSER' } | Remove-CimInstance
Remove-LocalUser -Name “IEUSER”
net user “IEUSER” /delete

Set-ItemProperty -Path "HKCU:\Software\Microsoft\Windows\CurrentVersion\Explorer\Advanced" -Name "TaskbarSmallIcons" -Type DWord -Value 1
Set-ItemProperty -Path "HKCU:\Software\Microsoft\Windows\CurrentVersion\Explorer\Advanced\People" -Name "PeopleBand" -Type DWord -Value 0
Set-ItemProperty -Path "HKCU:\Software\Microsoft\Windows\CurrentVersion\Search" -Name "SearchboxTaskbarMode" -Type DWord -Value 0
New-ItemProperty -Path "HKCU:\Software\Microsoft\Windows\CurrentVersion\Explorer\Advanced" -Name "TaskbarSizeMove" -Type DWord -Value 1
Set-ItemProperty -Path "HKCU:\Software\Microsoft\Windows\CurrentVersion\Explorer\Advanced" -Name "TaskbarGlomLevel" -Type DWord -Value 2

Stop-Process -Name "Explorer"

Invoke-WebRequest "https://totalcommander.ch/win/tcmd1000x32_64.exe" -OutFile "c:\WORK\tcmd.exe"
Invoke-WebRequest "https://github.com/go2tom42/win/raw/main/files/file1.bin" -OutFile "c:\WORK\wincmd.key"

start-process -FilePath "c:\WORK\tcmd.exe" -ArgumentList "/AHL0GDUK c:\totalcmd" -Wait -Passthru -NoNewWindow


