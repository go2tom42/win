
    New-Item -Path "c:\" -Name "WORK" -ItemType "directory"
    Set-Location c:\WORK
    Invoke-WebRequest "https://github.com/go2tom42/win/raw/main/files/EVAL.zip" -OutFile "c:\WORK\EVAL.zip"
    Expand-Archive -Path EVAL.zip -DestinationPath "c:\WORK"

    Start-Process -FilePath "powershell.exe" -ArgumentList "-File c:\WORK\init.ps1" -Verb RunAs