# ScreenCapture-TelegramBot
A PowerShell project that captures animated screen GIFs and sends system info via Telegram.


# ScreenCapture-TelegramBot

[![License: MIT](https://img.shields.io/badge/License-MIT-yellow.svg)](LICENSE)
[![PowerShell](https://img.shields.io/badge/PowerShell-v5.1%2B-blue.svg)](https://docs.microsoft.com/en-us/powershell/)

**ScreenCapture-TelegramBot** is a PowerShell project that captures animated screenshots over a defined duration and sends them—along with detailed system information—to a specified Telegram chat. It leverages Windows Location Services, network information, and native screen capture features to create a robust monitoring tool.

## Features

- **High DPI Awareness:** Ensures full-resolution capture on high DPI screens.
- **Encrypted Credentials:** Secure storage of bot tokens and chat IDs using DPAPI.
- **Animated Screen Capture:** Captures a 10-second animated GIF of your desktop.
- **Comprehensive System Info:** Gathers hardware, BIOS, network, and GPS location details.
- **Telegram Integration:** Automatically sends screenshots and system information to your Telegram chat.

## Getting Started

### Prerequisites

- Windows OS with PowerShell v5.1 or later.
- .NET Framework (for DPAPI and Windows Forms libraries).
- Telegram Bot Token and Chat ID.

### Installation

1. **Clone the repository:**

   ```bash
   git clone https://github.com/yourusername/ScreenCapture-TelegramBot.git
   cd ScreenCapture-TelegramBot
2. Configure Credentials:

   Edit the **CaptureAndSend.ps1** script to set your Telegram Bot Token and Chat ID. The script will automatically encrypt and 
   store these values on first run.

4. Run the Script:
   Open PowerShell and run:

```bash
   cd src
   .\CaptureAndSend.ps1
