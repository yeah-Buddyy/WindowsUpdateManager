# https://github.com/zoicware/WindowsUpdateManager

If (!([Security.Principal.WindowsPrincipal][Security.Principal.WindowsIdentity]::GetCurrent()).IsInRole([Security.Principal.WindowsBuiltInRole]'Administrator')) {
    Start-Process PowerShell.exe -ArgumentList ("-NoProfile -NoLogo -ExecutionPolicy Bypass -File `"{0}`"" -f $PSCommandPath) -Verb RunAs
    Exit	
}

$isDebug = $false

try {
    # Check if the PSWindowsUpdate module is already installed
    if (-not (Get-InstalledModule -Name PSWindowsUpdate -ErrorAction SilentlyContinue)) {
        Write-Host 'PSWindowsUpdate module not found. Installing...'
        
        # Install NuGet package provider if not already installed
        if (-not (Get-PackageProvider -Name NuGet -ErrorAction SilentlyContinue)) {
            Write-Host 'Installing NuGet package provider...'
            Install-PackageProvider -Name NuGet -MinimumVersion 2.8.5.201 -Force -ErrorAction Stop
        }
        
        # Install the PSWindowsUpdate module
        Install-Module -Name PSWindowsUpdate -SkipPublisherCheck -Force -ErrorAction Stop
        
        Write-Host 'PSWindowsUpdate module installed successfully.'
    } else {
        Write-Host 'PSWindowsUpdate module is already installed.'
    }
}
catch {
    Write-Host "An error occurred: $_"
    exit
}
finally {
    try {
        # Import the module, ensuring it is available for use
        Import-Module -Name PSWindowsUpdate -Force -ErrorAction Stop
        Write-Host 'PSWindowsUpdate module imported successfully.'
    } catch {
        Write-Host "Failed to import the PSWindowsUpdate module: $_"
        exit
    }
}

function getAutoUpdates {
    $settings = Get-WUSettings
    $autoUpdate = $settings.NoAutoUpdate
    return $autoUpdate
}

function getWUServer {
    $settings = Get-WUSettings
    $WUServer = $settings.WUServer
    return $WUServer
}

function getWUConnection {
    $settings = Get-WUSettings
    $WUCon = $settings.DoNotConnectToWindowsUpdateInternetLocations
    return $WUCon
}

function getWUService {
    $regkey = Get-ItemPropertyValue 'registry::HKLM\SYSTEM\CurrentControlSet\Services\UsoSvc' -Name 'Start'
    $uso = Get-WmiObject -Class Win32_Service | Where-Object { $_.Name -eq 'UsoSvc' }

    if ($regkey -eq '2' -and $uso.State -eq 'Running') {
        return 'WU Service Running and Enabled'

    }
    elseif ($regkey -eq '2' -and $uso.State -ne 'Running') {
        return 'WU Service needs restart'

    }
    else {
        return 'WU Service Disabled'
    } 
}

function getDOService {
    #get service
    $service = (Get-Service -Name DoSvc).Status
    if ($service -eq 'Running') {
        return 'Delivery Optimization Running'
    }
    else {
        return 'Delivery Optimization Stopped'
    }
}

function askWoody {
    param (
        [switch]$AsJob
    )

    $runAsJob = {
        # Define the URL of the webpage
        $url = "https://askwoody.com"

        # Create a WebRequest object with custom headers
        $request = [System.Net.HttpWebRequest]::Create($url)
        $request.UserAgent = "Mozilla/5.0 (Windows NT 10.0; Win64; x64; rv:91.0) Gecko/20100101 Firefox/91.0"
        $request.Headers.Add("Accept-Language", "en-US,en;q=0.5")
        $request.Headers.Add("Accept-Encoding", "gzip, deflate, br")
        $request.AutomaticDecompression = [System.Net.DecompressionMethods]::GZip -bor [System.Net.DecompressionMethods]::Deflate

        # Set the timeout to 10 seconds (10,000 milliseconds)
        $request.Timeout = 10000

        try {
            # Get the response from the server
            $response = $request.GetResponse()
            $reader = New-Object System.IO.StreamReader($response.GetResponseStream())
            $pageContent = $reader.ReadToEnd()
        } catch [System.Net.WebException] {
            Write-Host "$($_.Exception.Response)"
            return "Service currently unavailable"
        } finally {
            $reader.Close()
            $response.Close()
        }

        Write-Host "AskWoody StatusCode $([int]$response.StatusCode)"

        # Use a regular expression to find the level in the alt attribute
        $regex = 'alt="Microsoft Patch Defense Condition level (\d+)"'
        $match = [regex]::Match($pageContent, $regex)

        if ($match.Success) {
            $level = [int]$match.Groups[1].Value

            # Define the level messages
            $levelMessages = @{
                1 = "Current Microsoft patches are causing havoc. Don't patch."
                2 = "Patch reliability is unclear. Unless you have an immediate, pressing need to install a specific patch, don't do it."
                3 = "There are widespread problems with current patches. It is prudent to patch but check your results carefully."
                4 = "There are isolated problems with current patches, but they are well-known and documented here. Check askwoody.com to see if you're affected and if things look OK, go ahead and patch."
                5 = "All's clear. Patch while it's safe."
            }
        
            # Get the message corresponding to the level
            $message = $levelMessages[$level]
            Write-Host "Level $level $message"
            return $message
        } else {
            return "Service currently unavailable"
        }
    }
    if ($AsJob) {
        Start-Job $runAsJob
    }
}

if (-not($isDebug)) {
    # For additional PSWindowsUpdate debug information use $DebugPreference = "Continue"
    $DebugPreference = "Continue"

    # (0=hidden, ShowMinimized=2, etc: cf stackoverflow.com/a/40621143/1486850
    # Hide PowerShell Console
    Add-Type -Name Window -Namespace Console -MemberDefinition '
    [DllImport("Kernel32.dll")]
    public static extern IntPtr GetConsoleWindow();
    [DllImport("user32.dll")]
    public static extern bool ShowWindow(IntPtr hWnd, Int32 nCmdShow);
    '
    $consolePtr = [Console.Window]::GetConsoleWindow()
    [Console.Window]::ShowWindow($consolePtr, 0)
}

Add-Type -AssemblyName System.Windows.Forms
[System.Windows.Forms.Application]::EnableVisualStyles()

$backgroundColor = [System.Drawing.Color]::FromArgb(45, 45, 48)
    
$form = New-Object System.Windows.Forms.Form
$form.Text = 'Windows Update Manager'
$form.Size = New-Object System.Drawing.Size(1024, 768)
$form.StartPosition = 'CenterScreen'
$form.BackColor = 'Black'

# This base64 string holds the bytes that make up the dark update icon (just an example for a 32x32 pixel image)
# https://www.iconsdb.com/black-icons/available-updates-icon.html
$iconBase64 = 'AAABAAEAICAAAAEAIACoEAAAFgAAACgAAAAgAAAAQAAAAAEAIAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAGAAAAigAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAIYAAAD4AAAAEgAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA0AAAA+gAAAP8AAABcAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAABgAAANIAAAD/AAAA/wAAAKgAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAACCAAAA/wAAAP8AAAD/AAAA8gAAALAAAADKAAAA2gAAANoAAADIAAAAoAAAAGQAAAAWAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAMAAAAPgAAAD/AAAA/wAAAP8AAAD/AAAA/wAAAP8AAAD/AAAA/wAAAP8AAAD/AAAA/wAAAPgAAACeAAAAHgAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAQAAADMAAAA/wAAAP8AAAD/AAAA/wAAAP8AAAD/AAAA/wAAAP8AAAD/AAAA/wAAAP8AAAD/AAAA/wAAAP8AAADyAAAAYAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAeAAAAP8AAAD/AAAA/wAAAP8AAAD/AAAA/wAAAP8AAAD/AAAA/wAAAP8AAAD/AAAA/wAAAP8AAAD/AAAA/wAAAP8AAAD/AAAAhAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAACYAAAD2AAAA/wAAAP8AAAD/AAAA/wAAAP8AAAD/AAAA/wAAAP8AAAD/AAAA8gAAANgAAADUAAAA4AAAAPgAAAD/AAAA/wAAAP8AAAD/AAAAdgAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAApAAAAP8AAAD/AAAA/wAAAP8AAAD/AAAA/wAAAP8AAAD/AAAAqAAAAC4AAAACAAAAAAAAAAAAAAAAAAAABgAAAEIAAACcAAAA9AAAAP8AAAD8AAAAQAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAGAAAAYgAAANgAAAD/AAAA/wAAAP8AAAD/AAAA/wAAAP8AAACEAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAWAAAAjgAAAPgAAADaAAAABgAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAgAAAFQAAADIAAAA/wAAAP8AAAD/AAAA/wAAAMoAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAALgAAAM4AAABuAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAABAAAAAtAAAAPwAAAD/AAAA/AAAABQAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAACAAAAIAAAAAEAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAKgAAAJwAAAD2AAAAVAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAABgAAAAyAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAABMAAAANAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAABAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAFYAAAD/AAAAvAAAAEgAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAUAAAAjgAAAAYAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAFAAAAPwAAAD/AAAA/wAAANAAAABeAAAABgAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAACWAAAAzAAAACwAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAzAAAAP8AAAD/AAAA/wAAAP8AAADiAAAAdAAAAA4AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAABgAAADuAAAA+AAAAI4AAAAWAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAACGAAAA/wAAAP8AAAD/AAAA/wAAAP8AAAD/AAAA8AAAAIwAAAAcAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAF4AAAD/AAAA/wAAAPYAAACkAAAAUAAAABYAAAAAAAAAAAAAAAAAAAAQAAAASgAAALoAAAD/AAAA/wAAAP8AAAD/AAAA/wAAAP8AAAD/AAAA/wAAAMYAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAJAAAAD/AAAA/wAAAP8AAAD/AAAA/wAAAPIAAADoAAAA8AAAAP8AAAD/AAAA/wAAAP8AAAD/AAAA/wAAAP8AAAD/AAAA/wAAAP8AAAD6AAAAMgAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAgAAAJYAAAD/AAAA/wAAAP8AAAD/AAAA/wAAAP8AAAD/AAAA/wAAAP8AAAD/AAAA/wAAAP8AAAD/AAAA/wAAAP8AAAD/AAAA/wAAAIYAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAGwAAAD2AAAA/wAAAP8AAAD/AAAA/wAAAP8AAAD/AAAA/wAAAP8AAAD/AAAA/wAAAP8AAAD/AAAA/wAAAP8AAADUAAAACAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAACQAAACmAAAA+gAAAP8AAAD/AAAA/wAAAP8AAAD/AAAA/wAAAP8AAAD/AAAA/wAAAP8AAAD/AAAA+gAAADYAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAYAAAAZAAAAKAAAADCAAAAzgAAANAAAADGAAAArAAAAPQAAAD/AAAA/wAAAP8AAACIAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAArAAAAP8AAAD/AAAA1gAAAAgAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAABcAAAA/wAAAPoAAAA4AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAABIAAAD6AAAAigAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAI4AAAAIAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA/9////+f////n////w////4AP//+AAf//AAD//wAAP/4AAD/8AP4f/wD/j//A/+//8P/3//z///////////////////////////P//v/w//5/8D//H/AH/4fwA/+AAAf/wAAH//AAD//4AB///wAf///8P////n////5////+/8='
$iconBytes = [Convert]::FromBase64String($iconBase64)
# initialize a Memory stream holding the bytes
$stream = [System.IO.MemoryStream]::new($iconBytes, 0, $iconBytes.Length)
$form.Icon = [System.Drawing.Icon]::FromHandle(([System.Drawing.Bitmap]::new($stream).GetHIcon()))

$TabControl = New-Object System.Windows.Forms.TabControl
$TabControl.Dock = 'Fill'  # Dock the TabControl to fill the form
$TabControl.BackColor = $backgroundColor

$TabPage1 = New-Object System.Windows.Forms.TabPage
$TabPage1.Text = 'Update Configuration'
$TabPage1.BackColor = $backgroundColor

$TabPage2 = New-Object System.Windows.Forms.TabPage
$TabPage2.Text = 'Update Manager'
$TabPage2.BackColor = $backgroundColor

$TabControl.Controls.Add($TabPage1)
$TabControl.Controls.Add($TabPage2)
$form.Controls.Add($TabControl)

$label1 = New-Object System.Windows.Forms.Label
$label1.Location = New-Object System.Drawing.Point(10, 10)
$label1.Size = New-Object System.Drawing.Size(150, 25)
$label1.Text = 'Enable Options:'
$label1.ForeColor = 'White'
$label1.Font = New-Object System.Drawing.Font('Segoe UI', 13)  
$form.Controls.Add($label1)
$TabPage1.Controls.Add($label1)
      
$label2 = New-Object System.Windows.Forms.Label
$label2.Location = New-Object System.Drawing.Point(200, 10)  
$label2.Size = New-Object System.Drawing.Size(150, 25)
$label2.Text = 'Disable Options:'
$label2.ForeColor = 'White'
$label2.Font = New-Object System.Drawing.Font('Segoe UI', 13)  
$form.Controls.Add($label2)
$TabPage1.Controls.Add($label2)

$btn1 = New-Object Windows.Forms.Button
$btn1.Text = 'Disable Updates'
$btn1.Location = New-Object Drawing.Point(200, 40)
$btn1.Size = New-Object Drawing.Size(130, 35)
$btn1.Add_Click({
        Write-Host '-----------------DISABLING UPDATES-----------------'
        Reg.exe add 'HKLM\SOFTWARE\Policies\Microsoft\Windows\WindowsUpdate' /v 'WUServer' /t REG_SZ /d 'https://DoNotUpdateWindows10.com/' /f
        Reg.exe add 'HKLM\SOFTWARE\Policies\Microsoft\Windows\WindowsUpdate' /v 'WUStatusServer' /t REG_SZ /d 'https://DoNotUpdateWindows10.com/' /f
        Reg.exe add 'HKLM\SOFTWARE\Policies\Microsoft\Windows\WindowsUpdate' /v 'UpdateServiceUrlAlternate' /t REG_SZ /d 'https://DoNotUpdateWindows10.com/' /f
        Reg.exe add 'HKLM\SOFTWARE\Policies\Microsoft\Windows\WindowsUpdate' /v 'SetProxyBehaviorForUpdateDetection' /t REG_DWORD /d '0' /f
        Reg.exe add 'HKLM\SOFTWARE\Policies\Microsoft\Windows\WindowsUpdate' /v 'SetDisableUXWUAccess' /t REG_DWORD /d '1' /f
        Reg.exe add 'HKLM\SOFTWARE\Policies\Microsoft\Windows\WindowsUpdate' /v 'DoNotConnectToWindowsUpdateInternetLocations' /t REG_DWORD /d '1' /f
        Reg.exe add 'HKLM\SOFTWARE\Policies\Microsoft\Windows\WindowsUpdate' /v 'ExcludeWUDriversInQualityUpdate' /t REG_DWORD /d '1' /f
        Reg.exe add 'HKLM\SOFTWARE\Policies\Microsoft\Windows\WindowsUpdate\AU' /v 'NoAutoUpdate' /t REG_DWORD /d '1' /f
        Reg.exe add 'HKLM\SOFTWARE\Policies\Microsoft\Windows\WindowsUpdate\AU' /v 'UseWUServer' /t REG_DWORD /d '1' /f
        Reg.exe add 'HKLM\SYSTEM\CurrentControlSet\Services\UsoSvc' /v 'Start' /t REG_DWORD /d '4' /f
        gpupdate /force
        Write-Host '-----------------UPDATES DISABLED-----------------' 
    })

$form.Controls.Add($btn1)
$btn1.BackColor = [System.Drawing.Color]::FromArgb(30, 30, 30)
$btn1.ForeColor = [System.Drawing.Color]::White
$btn1.FlatStyle = [System.Windows.Forms.FlatStyle]::Flat
$btn1.FlatAppearance.BorderSize = 0
$btn1.FlatAppearance.MouseOverBackColor = [System.Drawing.Color]::FromArgb(62, 62, 64)
$btn1.FlatAppearance.MouseDownBackColor = [System.Drawing.Color]::FromArgb(27, 27, 28)
$TabPage1.Controls.Add($btn1)

$btn2 = New-Object Windows.Forms.Button
$btn2.Text = 'Pause Updates'
$btn2.Location = New-Object Drawing.Point(10, 80)
$btn2.Size = New-Object Drawing.Size(130, 35)
$btn2.Add_Click({
        Write-Host '-----------------PAUSING UPDATES-----------------'
        $form2 = New-Object System.Windows.Forms.Form
        $stream = [System.IO.MemoryStream]::new($iconBytes, 0, $iconBytes.Length)
        $form2.Icon = [System.Drawing.Icon]::FromHandle(([System.Drawing.Bitmap]::new($stream).GetHIcon()))
        $form2.Text = 'Pause Updates'
        $form2.Size = New-Object System.Drawing.Size(300, 150)
        $form2.StartPosition = 'CenterScreen'
        $form2.BackColor = [System.Drawing.Color]::FromArgb(45, 45, 48)

        $label = New-Object System.Windows.Forms.Label
        $label.Location = New-Object System.Drawing.Point(10, 20)
        $label.Size = New-Object System.Drawing.Size(280, 20)
        $label.Text = 'Enter the number of days to pause updates:'
        $label.ForeColor = 'White'
        $form2.Controls.Add($label)

        $textBox = New-Object System.Windows.Forms.TextBox
        $textBox.Location = New-Object System.Drawing.Point(10, 50)
        $textBox.Size = New-Object System.Drawing.Size(100, 20)
        #prevent letters from being typed
        $textBox.Add_KeyPress({
                param($sender, $e)
                # Check if the key pressed is not a digit or control key
                if (-not [char]::IsDigit($e.KeyChar) -and -not [char]::IsControl($e.KeyChar)) {
                    # If it's not, handle the event by setting Handled to true
                    $e.Handled = $true
                }
            })

        $form2.Controls.Add($textBox)

        $button = New-Object System.Windows.Forms.Button
        $button.Location = New-Object System.Drawing.Point(120, 80)
        $button.Size = New-Object System.Drawing.Size(75, 23)
        $button.Text = 'OK'
        $button.BackColor = [System.Drawing.Color]::FromArgb(30, 30, 30)
        $button.ForeColor = [System.Drawing.Color]::White
        $button.FlatStyle = [System.Windows.Forms.FlatStyle]::Flat
        $button.FlatAppearance.BorderSize = 0
        $button.FlatAppearance.MouseOverBackColor = [System.Drawing.Color]::FromArgb(62, 62, 64)
        $button.FlatAppearance.MouseDownBackColor = [System.Drawing.Color]::FromArgb(27, 27, 28)
        $button.Add_Click({
                $days = [int]$textBox.Text
                $form2.Close()

                if ($days -gt 500) {
                    Write-Host 'Days greater than 500...Pausing for MAX [500 days]'
                    $days = 500
                }

                $pause = (Get-Date).AddDays($days) 
                $today = Get-Date
                $today = $today.ToUniversalTime().ToString('yyyy-MM-ddTHH:mm:ssZ')
                $pause = $pause.ToUniversalTime().ToString('yyyy-MM-ddTHH:mm:ssZ')

                if (-not(Test-Path -Path "HKLM:\SOFTWARE\Microsoft\WindowsUpdate\UX\Settings")) {
                    New-Item -Path "HKLM:\SOFTWARE\Microsoft\WindowsUpdate\UX\Settings" -Force
                }
                Set-ItemProperty -Path 'HKLM:\SOFTWARE\Microsoft\WindowsUpdate\UX\Settings' -Name 'PauseUpdatesExpiryTime' -Value $pause -Force
                Set-ItemProperty -Path 'HKLM:\SOFTWARE\Microsoft\WindowsUpdate\UX\Settings' -Name 'PauseFeatureUpdatesEndTime' -Value $pause -Force
                Set-ItemProperty -Path 'HKLM:\SOFTWARE\Microsoft\WindowsUpdate\UX\Settings' -Name 'PauseFeatureUpdatesStartTime' -Value $today -Force
                Set-ItemProperty -Path 'HKLM:\SOFTWARE\Microsoft\WindowsUpdate\UX\Settings' -Name 'PauseQualityUpdatesEndTime' -Value $pause -Force
                Set-ItemProperty -Path 'HKLM:\SOFTWARE\Microsoft\WindowsUpdate\UX\Settings' -Name 'PauseQualityUpdatesStartTime' -Value $today -Force
                Set-ItemProperty -Path 'HKLM:\SOFTWARE\Microsoft\WindowsUpdate\UX\Settings' -Name 'PauseUpdatesStartTime' -Value $today -Force
                Write-Host "-----------------UPDATES PAUSED FOR $DAYS DAYS-----------------"    
            })

        $form2.Controls.Add($button)
        $form2.ShowDialog()
    })

$form.Controls.Add($btn2)
$btn2.BackColor = [System.Drawing.Color]::FromArgb(30, 30, 30)
$btn2.ForeColor = [System.Drawing.Color]::White
$btn2.FlatStyle = [System.Windows.Forms.FlatStyle]::Flat
$btn2.FlatAppearance.BorderSize = 0
$btn2.FlatAppearance.MouseOverBackColor = [System.Drawing.Color]::FromArgb(62, 62, 64)
$btn2.FlatAppearance.MouseDownBackColor = [System.Drawing.Color]::FromArgb(27, 27, 28)
$TabPage1.Controls.Add($btn2)

$btn3 = New-Object Windows.Forms.Button
$btn3.Text = 'Disable Drivers in Update'
$btn3.Location = New-Object Drawing.Point(200, 80)
$btn3.Size = New-Object Drawing.Size(130, 35)
$btn3.Add_Click({
        Write-Host '-----------------DISABLING DRIVERS IN WINDOWS UPDATE-----------------' 
        Reg.exe add 'HKLM\SOFTWARE\Policies\Microsoft\Windows\WindowsUpdate' /v 'ExcludeWUDriversInQualityUpdate' /t REG_DWORD /d '1' /f
        Reg.exe add 'HKLM\SOFTWARE\Microsoft\WindowsUpdate\UX\Settings' /v 'ExcludeWUDriversInQualityUpdate' /t REG_DWORD /d '1' /f
        gpupdate /force
        Write-Host '-----------------DRIVERS IN UPDATES DISABLED-----------------' 
    })

$form.Controls.Add($btn3)
$btn3.BackColor = [System.Drawing.Color]::FromArgb(30, 30, 30)
$btn3.ForeColor = [System.Drawing.Color]::White
$btn3.FlatStyle = [System.Windows.Forms.FlatStyle]::Flat
$btn3.FlatAppearance.BorderSize = 0
$btn3.FlatAppearance.MouseOverBackColor = [System.Drawing.Color]::FromArgb(62, 62, 64)
$btn3.FlatAppearance.MouseDownBackColor = [System.Drawing.Color]::FromArgb(27, 27, 28)
$TabPage1.Controls.Add($btn3)

$btn4 = New-Object Windows.Forms.Button
$btn4.Text = 'Disable Auto Driver Searching'
$btn4.Location = New-Object Drawing.Point(200, 160)
$btn4.Size = New-Object Drawing.Size(130, 35)
$btn4.Add_Click({
        Write-Host '-----------------DISABLING DRIVER SEARCHING-----------------'
        Reg.exe add 'HKLM\SOFTWARE\Microsoft\Windows\CurrentVersion\DriverSearching' /v 'SearchOrderConfig' /t REG_DWORD /d '0' /f
        Write-Host '-----------------DRIVER SEARCHING DISABLED-----------------'
    })

$form.Controls.Add($btn4)
$btn4.BackColor = [System.Drawing.Color]::FromArgb(30, 30, 30)
$btn4.ForeColor = [System.Drawing.Color]::White
$btn4.FlatStyle = [System.Windows.Forms.FlatStyle]::Flat
$btn4.FlatAppearance.BorderSize = 0
$btn4.FlatAppearance.MouseOverBackColor = [System.Drawing.Color]::FromArgb(62, 62, 64)
$btn4.FlatAppearance.MouseDownBackColor = [System.Drawing.Color]::FromArgb(27, 27, 28)
$TabPage1.Controls.Add($btn4)

$btn5 = New-Object Windows.Forms.Button
$btn5.Text = 'Disable Optional Updates'
$btn5.Location = New-Object Drawing.Point(200, 120)
$btn5.Size = New-Object Drawing.Size(130, 35)
$btn5.Add_Click({
        Write-Host '-----------------DISABLING OPTIONAL UPDATES (W11 ONLY)-----------------'
        Reg.exe add 'HKLM\SOFTWARE\Policies\Microsoft\Windows\WindowsUpdate' /v 'SetAllowOptionalContent' /t REG_DWORD /d '0' /f >$null
        gpupdate /force
        Write-Host '-----------------OPTIONAL UPDATES DISABLED-----------------'
    })

$form.Controls.Add($btn5)
$btn5.BackColor = [System.Drawing.Color]::FromArgb(30, 30, 30)
$btn5.ForeColor = [System.Drawing.Color]::White
$btn5.FlatStyle = [System.Windows.Forms.FlatStyle]::Flat
$btn5.FlatAppearance.BorderSize = 0
$btn5.FlatAppearance.MouseOverBackColor = [System.Drawing.Color]::FromArgb(62, 62, 64)
$btn5.FlatAppearance.MouseDownBackColor = [System.Drawing.Color]::FromArgb(27, 27, 28)
$TabPage1.Controls.Add($btn5)

$btn6 = New-Object Windows.Forms.Button
$btn6.Text = 'Enable Updates'
$btn6.Location = New-Object Drawing.Point(10, 40)
$btn6.Size = New-Object Drawing.Size(130, 35)
$btn6.Add_Click({
        Write-Host '-----------------ENABLING UPDATES-----------------'
        Reg.exe delete 'HKLM\SOFTWARE\Policies\Microsoft\Windows\WindowsUpdate' /v 'WUServer' /f
        Reg.exe delete 'HKLM\SOFTWARE\Policies\Microsoft\Windows\WindowsUpdate' /v 'WUStatusServer' /f
        Reg.exe delete 'HKLM\SOFTWARE\Policies\Microsoft\Windows\WindowsUpdate' /v 'UpdateServiceUrlAlternate' /f
        Reg.exe delete 'HKLM\SOFTWARE\Policies\Microsoft\Windows\WindowsUpdate' /v 'SetProxyBehaviorForUpdateDetection' /f
        Reg.exe delete 'HKLM\SOFTWARE\Policies\Microsoft\Windows\WindowsUpdate' /v 'SetDisableUXWUAccess' /f
        Reg.exe delete 'HKLM\SOFTWARE\Policies\Microsoft\Windows\WindowsUpdate' /v 'DoNotConnectToWindowsUpdateInternetLocations' /f
        Reg.exe delete 'HKLM\SOFTWARE\Policies\Microsoft\Windows\WindowsUpdate' /v 'ExcludeWUDriversInQualityUpdate' /f
        Reg.exe delete 'HKLM\SOFTWARE\Policies\Microsoft\Windows\WindowsUpdate\AU' /v 'NoAutoUpdate' /f
        Reg.exe delete 'HKLM\SOFTWARE\Policies\Microsoft\Windows\WindowsUpdate\AU' /v 'UseWUServer' /f
        Reg.exe add 'HKLM\SYSTEM\CurrentControlSet\Services\UsoSvc' /v 'Start' /t REG_DWORD /d '2' /f
        #remove pause values
        Reg.exe delete 'HKLM\SOFTWARE\Microsoft\WindowsUpdate\UX\Settings' /v 'PauseUpdatesExpiryTime' /f >$null 2>&1
        Reg.exe delete 'HKLM\SOFTWARE\Microsoft\WindowsUpdate\UX\Settings' /v 'PauseFeatureUpdatesEndTime' /f >$null 2>&1
        Reg.exe delete 'HKLM\SOFTWARE\Microsoft\WindowsUpdate\UX\Settings' /v 'PauseFeatureUpdatesStartTime' /f >$null 2>&1
        Reg.exe delete 'HKLM\SOFTWARE\Microsoft\WindowsUpdate\UX\Settings' /v 'PauseQualityUpdatesEndTime' /f >$null 2>&1
        Reg.exe delete 'HKLM\SOFTWARE\Microsoft\WindowsUpdate\UX\Settings' /v 'PauseQualityUpdatesStartTime' /f >$null 2>&1
        Reg.exe delete 'HKLM\SOFTWARE\Microsoft\WindowsUpdate\UX\Settings' /v 'PauseUpdatesStartTime' /f >$null 2>&1
        gpupdate /force
        Write-Host '-----------------UPDATES ENABLED-----------------'
    })

$form.Controls.Add($btn6)
$btn6.BackColor = [System.Drawing.Color]::FromArgb(30, 30, 30)
$btn6.ForeColor = [System.Drawing.Color]::White
$btn6.FlatStyle = [System.Windows.Forms.FlatStyle]::Flat
$btn6.FlatAppearance.BorderSize = 0
$btn6.FlatAppearance.MouseOverBackColor = [System.Drawing.Color]::FromArgb(62, 62, 64)
$btn6.FlatAppearance.MouseDownBackColor = [System.Drawing.Color]::FromArgb(27, 27, 28)
$TabPage1.Controls.Add($btn6)

$btn7 = New-Object Windows.Forms.Button
$btn7.Text = 'Disable Update Restart Notifications'
$btn7.Location = New-Object Drawing.Point(200, 200)
$btn7.Size = New-Object Drawing.Size(130, 35)
$btn7.Add_Click({
        Write-Host '-----------------DISABLING NOTIFICATIONS-----------------'
        Reg.exe add 'HKLM\SOFTWARE\Policies\Microsoft\Windows\WindowsUpdate\AU' /v 'NoAUShutdownOption' /t REG_DWORD /d '1' /f
        Reg.exe add 'HKLM\SOFTWARE\Microsoft\WindowsUpdate\UX\Settings' /v 'RestartNotificationsAllowed2' /t REG_DWORD /d '0' /f
        gpupdate /force
        Write-Host '-----------------NOTIFICATIONS DISABLED-----------------'  
    })

$form.Controls.Add($btn7)
$btn7.BackColor = [System.Drawing.Color]::FromArgb(30, 30, 30)
$btn7.ForeColor = [System.Drawing.Color]::White
$btn7.FlatStyle = [System.Windows.Forms.FlatStyle]::Flat
$btn7.FlatAppearance.BorderSize = 0
$btn7.FlatAppearance.MouseOverBackColor = [System.Drawing.Color]::FromArgb(62, 62, 64)
$btn7.FlatAppearance.MouseDownBackColor = [System.Drawing.Color]::FromArgb(27, 27, 28)
$TabPage1.Controls.Add($btn7)

$btn8 = New-Object Windows.Forms.Button
$btn8.Text = 'Defer Feature and Quality Updates'
$btn8.Location = New-Object Drawing.Point(200, 240)
$btn8.Size = New-Object Drawing.Size(130, 35)
$btn8.Add_Click({
        Write-Host '-----------------DEFERING FEATURE AND QUALITY UPDATES FOR [MAX] DAYS-----------------'
        Reg.exe add 'HKLM\SOFTWARE\Policies\Microsoft\Windows\WindowsUpdate' /v 'DeferFeatureUpdates' /t REG_DWORD /d '1' /f >$null
        Reg.exe add 'HKLM\SOFTWARE\Policies\Microsoft\Windows\WindowsUpdate' /v 'DeferFeatureUpdatesPeriodInDays' /t REG_DWORD /d '730' /f >$null
        Reg.exe add 'HKLM\SOFTWARE\Policies\Microsoft\Windows\WindowsUpdate' /v 'DeferQualityUpdates' /t REG_DWORD /d '1' /f >$null
        Reg.exe add 'HKLM\SOFTWARE\Policies\Microsoft\Windows\WindowsUpdate' /v 'DeferQualityUpdatesPeriodInDays' /t REG_DWORD /d '730' /f >$null
        gpupdate /force
        Write-Host '-----------------DEFERED FEATURE UPDATES QUALITY UPDATES-----------------'  
    })

$form.Controls.Add($btn8)
$btn8.BackColor = [System.Drawing.Color]::FromArgb(30, 30, 30)
$btn8.ForeColor = [System.Drawing.Color]::White
$btn8.FlatStyle = [System.Windows.Forms.FlatStyle]::Flat
$btn8.FlatAppearance.BorderSize = 0
$btn8.FlatAppearance.MouseOverBackColor = [System.Drawing.Color]::FromArgb(62, 62, 64)
$btn8.FlatAppearance.MouseDownBackColor = [System.Drawing.Color]::FromArgb(27, 27, 28)
$TabPage1.Controls.Add($btn8)

$btn9 = New-Object Windows.Forms.Button
$btn9.Text = 'Disable Delivery Optimization'
$btn9.Location = New-Object Drawing.Point(200, 280)
$btn9.Size = New-Object Drawing.Size(130, 35)
$btn9.Add_Click({
        Write-Host '-----------------DISABLING DELIVERY OPTIMIZATION-----------------'
        Stop-Service -Name DoSvc -Force -ErrorAction SilentlyContinue 
        Reg.exe add 'HKLM\SYSTEM\CurrentControlSet\Services\DoSvc' /v 'Start' /t REG_DWORD /d '4' /f
        Reg.exe add 'HKU\S-1-5-20\Software\Microsoft\Windows\CurrentVersion\DeliveryOptimization\Settings' /v 'DownloadMode' /t REG_DWORD /d '0' /f
        Write-Host '-----------------DISABLED DELIVERY OPTIMIZATION-----------------'  
    })

$form.Controls.Add($btn9)
$btn9.BackColor = [System.Drawing.Color]::FromArgb(30, 30, 30)
$btn9.ForeColor = [System.Drawing.Color]::White
$btn9.FlatStyle = [System.Windows.Forms.FlatStyle]::Flat
$btn9.FlatAppearance.BorderSize = 0
$btn9.FlatAppearance.MouseOverBackColor = [System.Drawing.Color]::FromArgb(62, 62, 64)
$btn9.FlatAppearance.MouseDownBackColor = [System.Drawing.Color]::FromArgb(27, 27, 28)
$TabPage1.Controls.Add($btn9)

$btn10 = New-Object Windows.Forms.Button
$btn10.Text = 'Enable Optional Updates'
$btn10.Location = New-Object Drawing.Point(10, 120)
$btn10.Size = New-Object Drawing.Size(130, 35)
$btn10.Add_Click({
        Write-Host '-----------------ENABLING OPTIONAL UPDATES-----------------'
        Reg.exe delete 'HKLM\SOFTWARE\Policies\Microsoft\Windows\WindowsUpdate' /v 'SetAllowOptionalContent' /f >$null
        gpupdate /force
        Write-Host '-----------------OPTIONAL UPDATES ENABLED-----------------'  
    })

$form.Controls.Add($btn10)
$btn10.BackColor = [System.Drawing.Color]::FromArgb(30, 30, 30)
$btn10.ForeColor = [System.Drawing.Color]::White
$btn10.FlatStyle = [System.Windows.Forms.FlatStyle]::Flat
$btn10.FlatAppearance.BorderSize = 0
$btn10.FlatAppearance.MouseOverBackColor = [System.Drawing.Color]::FromArgb(62, 62, 64)
$btn10.FlatAppearance.MouseDownBackColor = [System.Drawing.Color]::FromArgb(27, 27, 28)
$TabPage1.Controls.Add($btn10)

$btn11 = New-Object Windows.Forms.Button
$btn11.Text = 'Enable Auto Driver Searching'
$btn11.Location = New-Object Drawing.Point(10, 160)
$btn11.Size = New-Object Drawing.Size(130, 35)
$btn11.Add_Click({
        Write-Host '-----------------ENABLING AUTO DRIVER SEARCHING-----------------'
        Reg.exe add 'HKLM\SOFTWARE\Microsoft\Windows\CurrentVersion\DriverSearching' /v 'SearchOrderConfig' /t REG_DWORD /d '1' /f
        Write-Host '-----------------AUTO DRIVER SEARCHING ENABLED-----------------'  
    })

$form.Controls.Add($btn11)
$btn11.BackColor = [System.Drawing.Color]::FromArgb(30, 30, 30)
$btn11.ForeColor = [System.Drawing.Color]::White
$btn11.FlatStyle = [System.Windows.Forms.FlatStyle]::Flat
$btn11.FlatAppearance.BorderSize = 0
$btn11.FlatAppearance.MouseOverBackColor = [System.Drawing.Color]::FromArgb(62, 62, 64)
$btn11.FlatAppearance.MouseDownBackColor = [System.Drawing.Color]::FromArgb(27, 27, 28)
$TabPage1.Controls.Add($btn11)

$btn12 = New-Object Windows.Forms.Button
$btn12.Text = 'Enable Update Restart Notifications'
$btn12.Location = New-Object Drawing.Point(10, 200)
$btn12.Size = New-Object Drawing.Size(130, 35)
$btn12.Add_Click({
        Write-Host '-----------------ENABLING UPDATE RESTART NOTIFICATIONS-----------------'
        Reg.exe delete 'HKLM\SOFTWARE\Policies\Microsoft\Windows\WindowsUpdate\AU' /v 'NoAUShutdownOption' /f
        Reg.exe add 'HKLM\SOFTWARE\Microsoft\WindowsUpdate\UX\Settings' /v 'RestartNotificationsAllowed2' /t REG_DWORD /d '1' /f
        gpupdate /force
        Write-Host '-----------------UPDATE RESTART NOTIFICATIONS ENABLED-----------------'  
    })

$form.Controls.Add($btn12)
$btn12.BackColor = [System.Drawing.Color]::FromArgb(30, 30, 30)
$btn12.ForeColor = [System.Drawing.Color]::White
$btn12.FlatStyle = [System.Windows.Forms.FlatStyle]::Flat
$btn12.FlatAppearance.BorderSize = 0
$btn12.FlatAppearance.MouseOverBackColor = [System.Drawing.Color]::FromArgb(62, 62, 64)
$btn12.FlatAppearance.MouseDownBackColor = [System.Drawing.Color]::FromArgb(27, 27, 28)
$TabPage1.Controls.Add($btn12)

$btn13 = New-Object Windows.Forms.Button
$btn13.Text = 'Allow Feature and Quality Updates'
$btn13.Location = New-Object Drawing.Point(10, 240)
$btn13.Size = New-Object Drawing.Size(130, 35)
$btn13.Add_Click({
        Write-Host '-----------------ALLOWING FEATURE AND QUALITY UPDATES-----------------'
        Reg.exe delete 'HKLM\SOFTWARE\Policies\Microsoft\Windows\WindowsUpdate' /v 'DeferFeatureUpdates' /f 
        Reg.exe delete 'HKLM\SOFTWARE\Policies\Microsoft\Windows\WindowsUpdate' /v 'DeferFeatureUpdatesPeriodInDays' /f 
        Reg.exe delete 'HKLM\SOFTWARE\Policies\Microsoft\Windows\WindowsUpdate' /v 'DeferQualityUpdates' /f 
        Reg.exe delete 'HKLM\SOFTWARE\Policies\Microsoft\Windows\WindowsUpdate' /v 'DeferQualityUpdatesPeriodInDays' /f 
        gpupdate /force
        Write-Host '-----------------FEATURE AND QUALITY UPDATES ENABLED-----------------'  
    })

$form.Controls.Add($btn13)
$btn13.BackColor = [System.Drawing.Color]::FromArgb(30, 30, 30)
$btn13.ForeColor = [System.Drawing.Color]::White
$btn13.FlatStyle = [System.Windows.Forms.FlatStyle]::Flat
$btn13.FlatAppearance.BorderSize = 0
$btn13.FlatAppearance.MouseOverBackColor = [System.Drawing.Color]::FromArgb(62, 62, 64)
$btn13.FlatAppearance.MouseDownBackColor = [System.Drawing.Color]::FromArgb(27, 27, 28)
$TabPage1.Controls.Add($btn13)

$btn14 = New-Object Windows.Forms.Button
$btn14.Text = 'Enable Delivery Optimization'
$btn14.Location = New-Object Drawing.Point(10, 280)
$btn14.Size = New-Object Drawing.Size(130, 35)
$btn14.Add_Click({
        Write-Host '-----------------ENABLING DELIVERY OPTIMIZATION-----------------'
        Reg.exe add 'HKLM\SYSTEM\CurrentControlSet\Services\DoSvc' /v 'Start' /t REG_DWORD /d '2' /f
        Reg.exe add 'HKLM\SYSTEM\CurrentControlSet\Services\DoSvc' /v 'DelayedAutostart' /t REG_DWORD /d '1' /f
        Reg.exe delete 'HKU\S-1-5-20\Software\Microsoft\Windows\CurrentVersion\DeliveryOptimization\Settings' /v 'DownloadMode' /f
        Start-Service -Name DoSvc -ErrorAction SilentlyContinue 
        Write-Host '-----------------DELIVERY OPTIMIZATION ENABLED-----------------'  
    })

$form.Controls.Add($btn14)
$btn14.BackColor = [System.Drawing.Color]::FromArgb(30, 30, 30)
$btn14.ForeColor = [System.Drawing.Color]::White
$btn14.FlatStyle = [System.Windows.Forms.FlatStyle]::Flat
$btn14.FlatAppearance.BorderSize = 0
$btn14.FlatAppearance.MouseOverBackColor = [System.Drawing.Color]::FromArgb(62, 62, 64)
$btn14.FlatAppearance.MouseDownBackColor = [System.Drawing.Color]::FromArgb(27, 27, 28)
$TabPage1.Controls.Add($btn14)

#TAB 2

# Add a label above the log box
$logLabel = New-Object System.Windows.Forms.Label
$logLabel.Location = New-Object System.Drawing.Point(10, 490)
$logLabel.Size = New-Object System.Drawing.Size(760, 20)
$logLabel.Text = 'Log:'
$logLabel.Font = New-Object System.Drawing.Font("Segoe UI", 10, [System.Drawing.FontStyle]::Bold)
$logLabel.ForeColor = 'White'
$TabPage2.Controls.Add($logLabel)

# Create a RichTextBox for the log output
$logBox = New-Object System.Windows.Forms.RichTextBox
$logBox.Location = New-Object System.Drawing.Point(7, 520)
$logBox.Size = New-Object System.Drawing.Size(180, 180)
$logBox.ReadOnly = $true
$logBox.BackColor = 'Black'
$logBox.ForeColor = 'White'
$logBox.Font = New-Object System.Drawing.Font("Consolas", 10)
$logBox.Anchor = [System.Windows.Forms.AnchorStyles]::Top -bor `
                 [System.Windows.Forms.AnchorStyles]::Left -bor `
                 [System.Windows.Forms.AnchorStyles]::Right
$TabPage2.Controls.Add($logBox)

# Create a context menu with a "Copy" option
$contextMenu = New-Object System.Windows.Forms.ContextMenuStrip
$copyMenuItem = New-Object System.Windows.Forms.ToolStripMenuItem
$copyMenuItem.Text = "Copy"
$copyMenuItem.add_Click({
    $logBox.Copy()  # Copy selected text to clipboard
})

$contextMenu.Items.Add($copyMenuItem)
$logBox.ContextMenuStrip = $contextMenu

# Handle Ctrl+C key combination to copy text
$logBox.add_KeyDown({
    param($sender, $e)
    if ($e.Control -and $e.KeyCode -eq 'C') {
        $logBox.Copy()  # Copy selected text to clipboard
    }
})

# Function to append text to the log box
function Add-Log {
    param ([string]$text)
    $logBox.AppendText("$text`n")
    $logBox.ScrollToCaret()
}

# Function to prompt the user with a restart popup
function Show-RestartPrompt {
    if ((Get-WURebootStatus).RebootRequired) {
        $result = [System.Windows.Forms.MessageBox]::Show("Do you want to restart your computer? (Recommended)", "Restart Required", [System.Windows.Forms.MessageBoxButtons]::YesNo, [System.Windows.Forms.MessageBoxIcon]::Question)
        
        if ($result -eq [System.Windows.Forms.DialogResult]::Yes) {
            # Logic to restart the computer
            Write-Host "Restarting the computer.."
            Add-Log "Restarting the computer.."
            Restart-Computer -Force
        } else {
            Write-Host "Restart canceled."
            Add-Log "Restart canceled."
        }
    } else {
        Write-Host "No Restart Required."
        Add-Log "No Restart Required."
    }
}

$label = New-Object System.Windows.Forms.Label
$label.Location = New-Object System.Drawing.Point(10, 20)
$label.Size = New-Object System.Drawing.Size(280, 20)
$label.Text = 'Update Dependencies:'
$label.Font = New-Object System.Drawing.Font("Segoe UI", 10, [System.Drawing.FontStyle]::Bold)
$label.ForeColor = 'White'
$form.Controls.Add($label)
$TabPage2.Controls.Add($label)

$Global:label2 = New-Object System.Windows.Forms.Label
$Global:label3 = New-Object System.Windows.Forms.Label
$Global:label4 = New-Object System.Windows.Forms.Label
$Global:label5 = New-Object System.Windows.Forms.Label
$Global:label6 = New-Object System.Windows.Forms.Label

function getDependencies {
    $label2.Location = New-Object System.Drawing.Point(15, 40)
    $label2.Size = New-Object System.Drawing.Size(180, 20)
    if (getAutoUpdates -eq 1) { 
        $label2.Text = 'Auto Updates Disabled'
        $label2.ForeColor = 'Red'
    } else { 
        $label2.Text = 'Auto Updates Enabled'
        $label2.ForeColor = 'Green'
    }
    $form.Controls.Add($label2)
    $TabPage2.Controls.Add($label2)

    $server = getWUServer
    
    $label3.Location = New-Object System.Drawing.Point(15, 60)
    $label3.Size = New-Object System.Drawing.Size(200, 30)
    $label3.ForeColor = 'White'
    if ($null -eq $server) {
        $server = 'Default'
        $label3.Size = New-Object System.Drawing.Size(200, 20)
    }
    $label3.Text = "Windows Update Server: $server"
    $form.Controls.Add($label3)
    $TabPage2.Controls.Add($label3)

    if ($server -ne 'Default') {
        $label4.Location = New-Object System.Drawing.Point(15, 90)
    }
    else {
        $label4.Location = New-Object System.Drawing.Point(15, 80)
    }
    $label4.Size = New-Object System.Drawing.Size(180, 20)

    if (getWUConnection -eq 1) {
        $label4.Text = 'Connect to WU Server Disabled'
        $label4.ForeColor = 'Red'
    }
    else {
        $label4.Text = 'Connect to WU Server Enabled'
        $label4.ForeColor = 'Green'
    }
    $form.Controls.Add($label4)
    $TabPage2.Controls.Add($label4)

    if ($server -ne 'Default') {
        $label5.Location = New-Object System.Drawing.Point(15, 110)
    }
    else {
        $label5.Location = New-Object System.Drawing.Point(15, 100)
    }
    $label5.Size = New-Object System.Drawing.Size(180, 20)
    $text = getWUService
    if ($text -eq "WU Service Running and Enabled") {
        $label5.Text = $text
        $label5.ForeColor = 'Green'
    } elseif ($text -eq "WU Service needs restart") {
        $label5.Text = $text
        $label5.ForeColor = 'Yellow'
    } elseif ($text -eq "WU Service Disabled") {
        $label5.Text = $text
        $label5.ForeColor = 'Red'
    }
    $form.Controls.Add($label5)
    $TabPage2.Controls.Add($label5)

    if ($server -ne 'Default') {
        $label6.Location = New-Object System.Drawing.Point(15, 130)
    }
    else {
        $label6.Location = New-Object System.Drawing.Point(15, 120)
    }
    $label6.Size = New-Object System.Drawing.Size(180, 20)
    $text = getDOService
    if ($text -eq "Delivery Optimization Running") {
        $label6.Text = $text
        $label6.ForeColor = 'Green'
    } elseif ($text -eq "Delivery Optimization Stopped") {
        $label6.Text = $text
        $label6.ForeColor = 'Red'
    }
    $form.Controls.Add($label6)
    $TabPage2.Controls.Add($label6)
}
getDependencies

function refresh {
    $label2.Text = ''
    $label3.Text = ''
    $label4.Text = ''
    $label5.Text = ''
    $label6.Text = ''
    getDependencies
}

$label7 = New-Object System.Windows.Forms.Label
$label7.Location = New-Object System.Drawing.Point(450, 20)
$label7.Size = New-Object System.Drawing.Size(280, 20)
$label7.Text = 'Askwoody.com Status:'
$label7.Font = New-Object System.Drawing.Font("Segoe UI", 10, [System.Drawing.FontStyle]::Bold)
$label7.ForeColor = 'White'
$form.Controls.Add($label7)
$TabPage2.Controls.Add($label7)

$showAskWoodyFunc = {
    # New label with the text to be displayed under "Askwoody Status"
    $label8 = New-Object System.Windows.Forms.Label
    $label8.Location = New-Object System.Drawing.Point(450, 45)  # Adjusted Y-position to place it under $label7
    $label8.Size = New-Object System.Drawing.Size(280, 60)       # Adjusted size to fit the text

    $job = askWoody -AsJob

    # Check job status
    Write-Host "Job ID: $($job.Id), State: $($job.State)"

    # Wait for the job to complete
    Wait-Job $job

    # Get the job result
    $getAskWoody = Receive-Job $job

    # Clean up
    Remove-Job $job

    if ($getAskWoody -eq "Service currently unavailable") {
        $label8.Text = 'Service currently unavailable.'
        $label8.ForeColor = 'Red'
    } elseif ($getAskWoody -eq "Current Microsoft patches are causing havoc. Don't patch.") {
        $label8.Text = $getAskWoody
        $label8.ForeColor = 'Red'
    } elseif ($getAskWoody -eq "All's clear. Patch while it's safe.") {
        $label8.Text = $getAskWoody
        $label8.ForeColor = 'Green' 
    } elseif ($getAskWoody -eq "Patch reliability is unclear. Unless you have an immediate, pressing need to install a specific patch, don't do it.") {
        $label8.Text = $getAskWoody
        $label8.ForeColor = 'Yellow' 
    } elseif ($getAskWoody -eq "There are widespread problems with current patches. It is prudent to patch but check your results carefully.") {
        $label8.Text = $getAskWoody
        $label8.ForeColor = 'Orange' 
    } elseif ($getAskWoody -eq "There are isolated problems with current patches, but they are well-known and documented here. Check askwoody.com to see if you're affected and if things look OK, go ahead and patch.") {
        $label8.Text = $getAskWoody
        $label8.ForeColor = 'Blue' 
    }
    $label8.Font = $regularFont                                # Use a suitable font, e.g., $regularFont
    $TabPage2.Controls.Add($label8)
}

$showAskWoody = New-Object Windows.Forms.Button
$showAskWoody.Text = 'Check Askwoody'
$showAskWoody.Location = New-Object Drawing.Point(750, 40)
$showAskWoody.Size = New-Object Drawing.Size(120, 35)
$showAskWoody.Add_Click({
        Add-Log "Checking Askwoody.."
        &$showAskWoodyFunc
        Add-Log "Checking Askwoody finished"
    })

$form.Controls.Add($showAskWoody)
$showAskWoody.BackColor = [System.Drawing.Color]::FromArgb(30, 30, 30)
$showAskWoody.ForeColor = [System.Drawing.Color]::White
$showAskWoody.FlatStyle = [System.Windows.Forms.FlatStyle]::Flat
$showAskWoody.FlatAppearance.BorderSize = 0
$showAskWoody.FlatAppearance.MouseOverBackColor = [System.Drawing.Color]::FromArgb(62, 62, 64)
$showAskWoody.FlatAppearance.MouseDownBackColor = [System.Drawing.Color]::FromArgb(27, 27, 28)
$TabPage2.Controls.Add($showAskWoody)

$refreshBttn = New-Object Windows.Forms.Button
$refreshBttn.Text = 'Refresh'
$refreshBttn.Location = New-Object Drawing.Point(10, 155)
$refreshBttn.Size = New-Object Drawing.Size(70, 20)
$refreshBttn.Add_Click({
        Add-Log "Refreshing Dependencies.."
        refresh
        Add-Log "Refreshing finished"
    })

$form.Controls.Add($refreshBttn)
$refreshBttn.BackColor = [System.Drawing.Color]::FromArgb(30, 30, 30)
$refreshBttn.ForeColor = [System.Drawing.Color]::White
$refreshBttn.FlatStyle = [System.Windows.Forms.FlatStyle]::Flat
$refreshBttn.FlatAppearance.BorderSize = 0
$refreshBttn.FlatAppearance.MouseOverBackColor = [System.Drawing.Color]::FromArgb(62, 62, 64)
$refreshBttn.FlatAppearance.MouseDownBackColor = [System.Drawing.Color]::FromArgb(27, 27, 28)
$TabPage2.Controls.Add($refreshBttn)

$clearDOcache = New-Object Windows.Forms.Button
$clearDOcache.Text = 'Clear Delivery Optimization Cache'
$clearDOcache.Location = New-Object Drawing.Point(250, 40)
$clearDOcache.Size = New-Object Drawing.Size(120, 35)
$clearDOcache.Add_Click({
        #clear delivery optmization cache
        Write-Host 'Clearing Delivery Optimization Cache..'
        Add-Log "Clearing Delivery Optimization Cache.."
        try {
            #will error if dosvc is disabled 
            Delete-DeliveryOptimizationCache -Force -ErrorAction Stop
        }
        catch {
            #delete cache manually
            if (Test-Path -Path "$Env:WinDir\ServiceProfiles\NetworkService\AppData\Local\Microsoft\Windows\DeliveryOptimization\Cache\*") {
                Remove-Item -Path "$Env:WinDir\ServiceProfiles\NetworkService\AppData\Local\Microsoft\Windows\DeliveryOptimization\Cache\*" -Force -Recurse
            }
        }
        Write-Host 'Cleared Delivery Optimization Cache'
        Add-Log "Cleared Delivery Optimization Cache"
    })

$form.Controls.Add($clearDOcache)
$clearDOcache.BackColor = [System.Drawing.Color]::FromArgb(30, 30, 30)
$clearDOcache.ForeColor = [System.Drawing.Color]::White
$clearDOcache.FlatStyle = [System.Windows.Forms.FlatStyle]::Flat
$clearDOcache.FlatAppearance.BorderSize = 0
$clearDOcache.FlatAppearance.MouseOverBackColor = [System.Drawing.Color]::FromArgb(62, 62, 64)
$clearDOcache.FlatAppearance.MouseDownBackColor = [System.Drawing.Color]::FromArgb(27, 27, 28)
$TabPage2.Controls.Add($clearDOcache)

$clearUpdateCache = New-Object Windows.Forms.Button
$clearUpdateCache.Text = 'Clear Windows Update Cache'
$clearUpdateCache.Location = New-Object Drawing.Point(250, 90)
$clearUpdateCache.Size = New-Object Drawing.Size(120, 35)
$clearUpdateCache.Add_Click({
        # Only recommended if there are no pending Windows updates.
        $getWindowsUpdate = Get-WindowsUpdate -WindowsUpdate

        if (-not($getWindowsUpdate)) {
            Write-Host "Clearing Windows Update Cache.."
            Add-Log "Clearing Windows Update Cache.."
            $softwareDistributionDownloadFolderPath = "$env:WINDIR\SoftwareDistribution\Download"
            try {
                #clear windows update cache
                $wusvc = (Get-Service -Name wuauserv).Status
                $bits = (Get-Service -Name BITS).Status
                if (!($wusvc -eq 'Stopped')) {
                    Stop-Service -Name wuauserv -Force
                }
                if (!($bits -eq 'Stopped')) {
                    Stop-Service -Name BITS -Force
                }
        
                # Clear the contents of the Download folder
                Get-ChildItem -Path $softwareDistributionDownloadFolderPath -Recurse | ForEach-Object {
                    try {
                        Remove-Item -Path $_.FullName -Recurse -Force -ErrorAction Stop
                        Write-Host "Deleted: $($_.FullName)" -ForegroundColor Yellow
                    } catch {
                        Write-Host "Failed to delete $($_.FullName): $_" -ForegroundColor Red
                    }
                }
        
                #start the services again if they were running 
                if (!($wusvc -eq 'Stopped')) {
                    Start-Service -Name wuauserv 
                }
                if (!($bits -eq 'Stopped')) {
                    Start-Service -Name BITS 
                }
        
                Write-Host "Cleared all folders and files from $softwareDistributionDownloadFolderPath successfully."
            } catch {
                Write-Error "An error occurred while clearing $softwareDistributionDownloadFolderPath $_"
            }
            Write-Host "Cleared Windows Update Cache"
            Add-Log "Cleared Windows Update Cache"
        } else {
            Write-Host "Failed to clear the Windows Update cache because you have pending updates"
            Add-Log "Failed to clear the Windows Update cache because you have pending updates"
        }
    })
    
$form.Controls.Add($clearUpdateCache)
$clearUpdateCache.BackColor = [System.Drawing.Color]::FromArgb(30, 30, 30)
$clearUpdateCache.ForeColor = [System.Drawing.Color]::White
$clearUpdateCache.FlatStyle = [System.Windows.Forms.FlatStyle]::Flat
$clearUpdateCache.FlatAppearance.BorderSize = 0
$clearUpdateCache.FlatAppearance.MouseOverBackColor = [System.Drawing.Color]::FromArgb(62, 62, 64)
$clearUpdateCache.FlatAppearance.MouseDownBackColor = [System.Drawing.Color]::FromArgb(27, 27, 28)
$TabPage2.Controls.Add($clearUpdateCache)

$checkingUpdates = New-Object System.Windows.Forms.Label
$checkingUpdates.Location = New-Object System.Drawing.Point(10, 200)
$checkingUpdates.Size = New-Object System.Drawing.Size(180, 20)
$checkingUpdates.ForeColor = 'White'
$checkingUpdates.BackColor = 'Black'
$checkingUpdates.Text = 'Searching For Updates..' 
$checkingUpdates.Visible = $false
$TabPage2.Controls.Add($checkingUpdates)

$checkingUpdatesDriver = New-Object System.Windows.Forms.Label
$checkingUpdatesDriver.Location = New-Object System.Drawing.Point(10, 200)
$checkingUpdatesDriver.Size = New-Object System.Drawing.Size(180, 20)
$checkingUpdatesDriver.ForeColor = 'White'
$checkingUpdatesDriver.BackColor = 'Black'
$checkingUpdatesDriver.Text = 'Searching For Driver Updates..' 
$checkingUpdatesDriver.Visible = $false
$TabPage2.Controls.Add($checkingUpdatesDriver)

$noDriverUpdates = New-Object System.Windows.Forms.Label
$noDriverUpdates.Location = New-Object System.Drawing.Point(10, 200)
$noDriverUpdates.Size = New-Object System.Drawing.Size(180, 20)
$noDriverUpdates.ForeColor = 'White'
$noDriverUpdates.BackColor = 'Black'
$noDriverUpdates.Text = 'No Driver Updates Found..' 
$noDriverUpdates.Visible = $false
$TabPage2.Controls.Add($noDriverUpdates)

$noUpdates = New-Object System.Windows.Forms.Label
$noUpdates.Location = New-Object System.Drawing.Point(10, 200)
$noUpdates.Size = New-Object System.Drawing.Size(180, 20)
$noUpdates.ForeColor = 'White'
$noUpdates.BackColor = 'Black'
$noUpdates.Text = 'No Updates Found..' 
$noUpdates.Visible = $false
$TabPage2.Controls.Add($noUpdates)

$checkedListBox = New-Object System.Windows.Forms.CheckedListBox
$checkedListBox.Location = New-Object System.Drawing.Point(7, 190)
$checkedListBox.Size = New-Object System.Drawing.Size(180, 120)
$checkedListBox.BackColor = 'Black'
$checkedListBox.ForeColor = 'White'
$checkedListBox.ScrollAlwaysVisible = $false
$checkedListBox.CheckOnClick = $true
$checkedListBox.Anchor = [System.Windows.Forms.AnchorStyles]::Top -bor `
                 [System.Windows.Forms.AnchorStyles]::Left -bor `
                 [System.Windows.Forms.AnchorStyles]::Right

# Create a ContextMenuStrip for right-click options
$contextMenu = New-Object System.Windows.Forms.ContextMenuStrip
$copyMenuItem = $contextMenu.Items.Add("Copy")
# Add "Check All" option to context menu
$markAllMenuItem = $contextMenu.Items.Add("Check All")
# Add "Unmark All" option to context menu
$unmarkAllMenuItem = $contextMenu.Items.Add("Uncheck All")
# Attach the context menu to the CheckedListBox
$checkedListBox.ContextMenuStrip = $contextMenu
# Add event handler for the "Copy" menu item
$copyMenuItem.Add_Click({
    $selectedItems = $checkedListBox.SelectedItems
    if ($selectedItems.Count -gt 0) {
        $clipboardText = $selectedItems -join "`n"
        [System.Windows.Forms.Clipboard]::SetText($clipboardText)
    }
})

# Add event handler for the "Check All" menu item
$markAllMenuItem.Add_Click({
    for ($i = 0; $i -lt $checkedListBox.Items.Count; $i++) {
        $checkedListBox.SetItemChecked($i, $true)
    }
})

# Add event handler for the "Uncheck All" menu item
$unmarkAllMenuItem.Add_Click({
    for ($i = 0; $i -lt $checkedListBox.Items.Count; $i++) {
        $checkedListBox.SetItemChecked($i, $false)
    }
})

# Handle Ctrl+C for copying and Ctrl+A/Ctrl+U for selecting all/unmarking all
$form.KeyPreview = $true
$form.Add_KeyDown({
    param($sender, $e)
    
    if ($e.Control -and $e.KeyCode -eq 'C') {
        $selectedItems = $checkedListBox.SelectedItems
        if ($selectedItems.Count -gt 0) {
            $clipboardText = $selectedItems -join "`n"
            [System.Windows.Forms.Clipboard]::SetText($clipboardText)
        }
    }
    elseif ($e.Control -and $e.KeyCode -eq 'A') {
        for ($i = 0; $i -lt $checkedListBox.Items.Count; $i++) {
            $checkedListBox.SetItemChecked($i, $true)
        }
    }
    elseif ($e.Control -and $e.KeyCode -eq 'U') {
        for ($i = 0; $i -lt $checkedListBox.Items.Count; $i++) {
            $checkedListBox.SetItemChecked($i, $false)
        }
    }
})

# Hashtable to store additional details for each item
$updateDetails = @{}

# Create a ToolTip object
$toolTip = New-Object System.Windows.Forms.ToolTip
$toolTip.AutoPopDelay = 5000
$toolTip.InitialDelay = 1000
$toolTip.ReshowDelay = 500
$toolTip.ShowAlways = $true

# Handle the MouseMove event to dynamically set the tooltip text
$checkedListBox.Add_MouseMove({
    param($sender, $e)

    # Determine the item index based on the mouse position
    $index = $checkedListBox.IndexFromPoint($e.Location)

    if ($index -ge 0 -and $index -lt $checkedListBox.Items.Count) {
        # Get the item title at the index
        $itemTitle = $checkedListBox.Items[$index]

        # Retrieve the corresponding details from the hashtable
        $itemDetails = $updateDetails[$itemTitle]

        # Set the tooltip text to show the description and size
        $tooltipText = "Title: " + $itemDetails.Title + "`nPublished: " + $itemDetails.Published + "`nDescription: " + $itemDetails.Description + "`nSize: " + $itemDetails.Size
        $toolTip.SetToolTip($checkedListBox, $tooltipText)
    } else {
        # Clear the tooltip if the mouse is not over an item
        $toolTip.SetToolTip($checkedListBox, $null)
    }
})

$TabPage2.Controls.Add($checkedListBox)

$checkForUpdate = {
    $noDriverUpdates.Visible = $false
    $noUpdates.Visible = $false
    $showOnlyDriver.Checked = $false

    $checkingUpdates.Visible = $true
    $form.Refresh()
    $checkedListBox.Items.Clear()
    if ($isDebug) {
        try {
            Write-Host "Searching for Windows Updates.."
            $Global:updates = Get-WindowsUpdate -MicrosoftUpdate -Verbose -Debuger -ErrorAction Stop
            $result = $Global:updates
            $result | Format-Table -AutoSize
            Write-Host "Searching for Windows Updates finished"
        } catch {
            Write-Host "Failed searching for Windows Updates"
            Write-Host "Error Message: $($_.Exception.Message)"
            Write-Host "Error Details: $($_.Exception)"
        }
    } else {
        try {
            Add-Log "Searching for Windows Updates.."
            $Global:updates = Get-WindowsUpdate -MicrosoftUpdate -ErrorAction Stop
            Add-Log "Searching for Windows Updates finished"
        } catch {
            Add-Log "Failed searching for Windows Updates"
        }
    }
    if (!$updates) {
        $noUpdates.Visible = $true
    }
    else {
        foreach ($update in $updates) {
            $checkedListBox.Items.Add($update.Title, $false)
            $updateDetails[$update.Title] = [PSCustomObject]@{ Title = $update.Title; Published = $update.LastDeploymentChangeTime; Description = $update.Description; Size = $update.Size }
        }
        
        if ($checkedListBox.Items.Count -gt 7) {
            $checkedListBox.ScrollAlwaysVisible = $true
        }
    }
    
    $checkingUpdates.Visible = $false
}

$checkUpdate = New-Object Windows.Forms.Button
$checkUpdate.Text = 'Check for Updates'
$checkUpdate.Location = New-Object Drawing.Point(10, 310)
$checkUpdate.Size = New-Object Drawing.Size(120, 35)
$checkUpdate.Add_Click({
        &$checkForUpdate
    })

$form.Controls.Add($checkUpdate)
$checkUpdate.BackColor = [System.Drawing.Color]::FromArgb(30, 30, 30)
$checkUpdate.ForeColor = [System.Drawing.Color]::White
$checkUpdate.FlatStyle = [System.Windows.Forms.FlatStyle]::Flat
$checkUpdate.FlatAppearance.BorderSize = 0
$checkUpdate.FlatAppearance.MouseOverBackColor = [System.Drawing.Color]::FromArgb(62, 62, 64)
$checkUpdate.FlatAppearance.MouseDownBackColor = [System.Drawing.Color]::FromArgb(27, 27, 28)
$TabPage2.Controls.Add($checkUpdate)

$installSelectedUpdate = {
    if ($checkedListBox.CheckedItems.Count -le 0) {
        Add-Log "No items are selected (checked)."
        return
    }

    # Create a list to hold selected updates and their details
    $selectedUpdatesWithDates = @()

    Write-Host 'Gathering Selected Updates'
    foreach ($selectedUpdate in $checkedListBox.CheckedItems.GetEnumerator()) {
        $revisionNumber = $null  # Initialize or reset for each iteration
        $updateId = $null  # Initialize or reset for each iteration
        $updatePublishedDate = $null  # Initialize or reset for each iteration

        if ($updates) {
            foreach ($update in $updates) {
                if ($update.Title -eq $selectedUpdate) {
                    $revisionNumber = $update.Identity.RevisionNumber
                    $updateId = $update.Identity.UpdateID
                    $updatePublishedDate = $update.LastDeploymentChangeTime
                    break
                }
            }
        } else {
            # Handle driver updates
            foreach ($driverUpdate in $driverUpdates) {
                if ($driverUpdate.Title -eq $selectedUpdate) {
                    $revisionNumber = $driverUpdate.Identity.RevisionNumber
                    $updateId = $driverUpdate.Identity.UpdateID
                    $updatePublishedDate = $driverUpdate.LastDeploymentChangeTime
                    break
                }
            }
        }

        #Write-Host "RevisionNumber: $revisionNumber"
        #Write-Host "UpdateID: $updateId"
        #Add-Log "Update Published Date: $updatePublishedDate"

        if ($null -ne $revisionNumber -and $null -ne $updateId -and $null -ne $updatePublishedDate) {
            # Store the update's details in the list
            $selectedUpdatesWithDates += [PSCustomObject]@{
                Title            = $selectedUpdate
                RevisionNumber   = $revisionNumber
                UpdateID         = $updateId
                PublishedDate    = $updatePublishedDate
            }
        }
    }

    # Sort the updates by PublishedDate (ascending)
    $sortedUpdates = $selectedUpdatesWithDates | Sort-Object PublishedDate

    Write-Host 'Installing Selected Updates by Date Order'
    foreach ($update in $sortedUpdates) {
        $successfullyInstalled = $false  # Flag to track successful installation

        if ($isDebug) {
            try {
                Write-Host "Installing update:", $update.Title
                $result = Install-WindowsUpdate -UpdateID "$($update.UpdateID)" -RevisionNumber "$($update.RevisionNumber)" -AcceptAll -IgnoreReboot -MicrosoftUpdate -Verbose -Debuger -ErrorAction Stop
                $result | Format-Table -AutoSize
                if ($result.Result -contains "Failed") {
                    Write-Host "Update installation failed $($update.Title)"
                } elseif ($result.Result -contains "Succeeded") {
                    Write-Host "Update installation completed successfully."
                    $successfullyInstalled = $true  # Mark as successfully installed
                } elseif ($result.Result -contains "InProgress") {
                    Write-Host "Update installation completed successfully."
                    $successfullyInstalled = $true  # Mark as successfully installed
                }
            } catch {
                Write-Host "Update installation failed $($update.Title)"
                Write-Host "Error Message: $($_.Exception.Message)"
                Write-Host "Error Details: $($_.Exception)"
            }
        } else {
            try {
                Add-Log "Installing $($update.Title)"
                $result = Install-WindowsUpdate -UpdateID "$($update.UpdateID)" -RevisionNumber "$($update.RevisionNumber)" -AcceptAll -IgnoreReboot -MicrosoftUpdate -ErrorAction Stop
                if ($result.Result -contains "Failed") {
                    Add-Log "Update installation failed $($update.Title)"
                } elseif ($result.Result -contains "Succeeded") {
                    Add-Log "Update installation completed successfully $($update.Title)"
                    $successfullyInstalled = $true  # Mark as successfully installed
                } elseif ($result.Result -contains "InProgress") {
                    Add-Log "Update installation completed successfully $($update.Title)"
                    $successfullyInstalled = $true  # Mark as successfully installed
                }
            } catch {
                Add-Log "Update installation failed $($update.Title)"
            }
        }
        
        # Remove the item from the CheckedListBox if successfully installed
        if ($successfullyInstalled) {
            $checkedListBox.Items.Remove($selectedUpdate)
        }
    }

    # Start a loop to continuously check the installer status
    while ((Get-WUInstallerStatus).IsBusy) {
        Write-Host "Installer status currently busy.."
        Add-Log "Installer status currently busy.."
        Start-Sleep -Seconds 5
    }

    Write-Host 'Check whether a restart is required to complete the installation of updates'
    Add-Log "Check whether a restart is required to complete the installation of updates"
    Show-RestartPrompt
}

$installSelected = New-Object Windows.Forms.Button
$installSelected.Text = 'Install Selected Updates'
$installSelected.Location = New-Object Drawing.Point(140, 310)
$installSelected.Size = New-Object Drawing.Size(120, 35)
$installSelected.Add_Click({
        &$installSelectedUpdate
    })

$form.Controls.Add($installSelected)
$installSelected.BackColor = [System.Drawing.Color]::FromArgb(30, 30, 30)
$installSelected.ForeColor = [System.Drawing.Color]::White
$installSelected.FlatStyle = [System.Windows.Forms.FlatStyle]::Flat
$installSelected.FlatAppearance.BorderSize = 0
$installSelected.FlatAppearance.MouseOverBackColor = [System.Drawing.Color]::FromArgb(62, 62, 64)
$installSelected.FlatAppearance.MouseDownBackColor = [System.Drawing.Color]::FromArgb(27, 27, 28)
$TabPage2.Controls.Add($installSelected)

<#
$installAllUpdates = {
    Write-Host 'Installing All Updates'
    #check update server
    $server = getWUServer
    $serverConnect = getWUConnection
    if ($server -ne $null -or $serverConnect) {
        #enable connection so that get-windowsupdate works
        Write-host 'Connect to Windows Update Location Disabled..'
        Add-Log "Connect to Windows Update Location Disabled.."
        Write-Host 'Enabling Connection'
        Add-Log "Enabling Connection"
        Reg.exe delete 'HKLM\SOFTWARE\Policies\Microsoft\Windows\WindowsUpdate' /v 'DoNotConnectToWindowsUpdateInternetLocations' /f >$null 2>&1
        Reg.exe delete 'HKLM\SOFTWARE\Policies\Microsoft\Windows\WindowsUpdate' /v 'WUServer' /f >$null 2>&1
        Reg.exe delete 'HKLM\SOFTWARE\Policies\Microsoft\Windows\WindowsUpdate' /v 'WUStatusServer' /f >$null 2>&1
        Reg.exe delete 'HKLM\SOFTWARE\Policies\Microsoft\Windows\WindowsUpdate' /v 'UpdateServiceUrlAlternate' /f >$null 2>&1
    }
    
    if ($isDebug) {
        try {
            Write-Host 'Searching for Windows Updates..'
            $allupdates = Get-WindowsUpdate -MicrosoftUpdate -Verbose -Debuger
            $result = $allupdates
            $result | Format-Table -AutoSize
            Write-Host "Searching for Windows Updates finished"
        } catch {
            Write-Host "Failed searching for Windows Updates"
            Write-Host "Error Message: $($_.Exception.Message)"
            Write-Host "Error Details: $($_.Exception)"
        }
    } else {
        try {
            Add-Log "Searching for Windows Updates.."
            $allupdates = Get-WindowsUpdate -MicrosoftUpdate
            Add-Log "Searching for Windows Updates finished"
        } catch {
            Add-Log "Failed searching for Windows Updates"
        }
    }
    if (!$allupdates) {
        Write-Host 'No Updates Found'
        Add-Log "No Updates Found"
    }
    else {
        foreach ($update in $allupdates) {
            $revisionNumber = $null  # Initialize or reset for each iteration
            $updateId = $null  # Initialize or reset for each iteration

            $revisionNumber = $update.Identity.RevisionNumber
            $updateId = $update.Identity.UpdateID
            #Write-Host "RevisionNumber: $revisionNumber"
            #Write-Host "UpdateID: $updateId"

            if ($null -ne $revisionNumber -and $null -ne $updateId) {
                if ($isDebug) {
                    try {
                        Write-Host "Installing update:", $update.Title
                        $result = Install-WindowsUpdate -UpdateID "$updateId" -RevisionNumber "$revisionNumber" -AcceptAll -IgnoreReboot -MicrosoftUpdate -Verbose -Debuger
                        $result | Format-Table -AutoSize
                        if ($result.Result -contains "Failed") {
                            Write-Host "Update installation failed $($update.Title)"
                        } else {
                            Write-Host "Update installation completed successfully."
                            foreach ($updateItem in $checkedListBox.Items) {
                                if ($update.Title -eq $updateItem) {
                                    $checkedListBox.Items.Remove($updateItem)
                                }
                            }
                        }
                    } catch {
                        Write-Host "Update installation failed $($update.Title)"
                        Write-Host "Error Message: $($_.Exception.Message)"
                        Write-Host "Error Details: $($_.Exception)"
                    }
                } else {
                    try {
                        Add-Log "Installing update:", $update.Title
                        $result = Install-WindowsUpdate -UpdateID "$updateId" -RevisionNumber "$revisionNumber" -AcceptAll -IgnoreReboot -MicrosoftUpdate
                        if ($result.Result -contains "Failed") {
                            Add-Log "Update installation failed $($update.Title)"
                        } else {
                            Add-Log "Update installation completed successfully"
                            foreach ($updateItem in $checkedListBox.Items) {
                                if ($update.Title -eq $updateItem) {
                                    $checkedListBox.Items.Remove($updateItem)
                                }
                            }
                        }
                    } catch {
                        Add-Log "Update installation failed $($update.Title)"
                    }
                }
            }
        }

        if ($null -ne $server -or $serverConnect) {
            Write-Host 'Disabling Windows Update Location Connectivity'
            Add-Log "Disabling Windows Update Location Connectivity"
            Reg.exe add 'HKLM\SOFTWARE\Policies\Microsoft\Windows\WindowsUpdate' /v 'WUServer' /t REG_SZ /d 'https://DoNotUpdateWindows10.com/' /f
            Reg.exe add 'HKLM\SOFTWARE\Policies\Microsoft\Windows\WindowsUpdate' /v 'WUStatusServer' /t REG_SZ /d 'https://DoNotUpdateWindows10.com/' /f
            Reg.exe add 'HKLM\SOFTWARE\Policies\Microsoft\Windows\WindowsUpdate' /v 'UpdateServiceUrlAlternate' /t REG_SZ /d 'https://DoNotUpdateWindows10.com/' /f
            Reg.exe add 'HKLM\SOFTWARE\Policies\Microsoft\Windows\WindowsUpdate' /v 'DoNotConnectToWindowsUpdateInternetLocations' /t REG_DWORD /d '1' /f 
        }
        
        # Start a loop to continuously check the installer status
        while ((Get-WUInstallerStatus).IsBusy) {
            Write-Host "Installer status currently busy.."
            Add-Log "Installer status currently busy.."
            Start-Sleep -Seconds 3
        }

        Write-Host 'Check whether a restart is required to complete the installation of updates'
        Add-Log "Check whether a restart is required to complete the installation of updates"
        Show-RestartPrompt
    }
}

$installALL = New-Object Windows.Forms.Button
$installALL.Text = 'Install All Updates'
$installALL.Location = New-Object Drawing.Point(270, 310)
$installALL.Size = New-Object Drawing.Size(120, 35)
$installALL.Add_Click({
        &$installAllUpdates
    })

$form.Controls.Add($installALL)
$installALL.BackColor = [System.Drawing.Color]::FromArgb(30, 30, 30)
$installALL.ForeColor = [System.Drawing.Color]::White
$installALL.FlatStyle = [System.Windows.Forms.FlatStyle]::Flat
$installALL.FlatAppearance.BorderSize = 0
$installALL.FlatAppearance.MouseOverBackColor = [System.Drawing.Color]::FromArgb(62, 62, 64)
$installALL.FlatAppearance.MouseDownBackColor = [System.Drawing.Color]::FromArgb(27, 27, 28)
$TabPage2.Controls.Add($installALL)
#>

$showHiddenUpdatesFunc = {
    if ($isDebug) {
        try {
            Write-Host "Searching for Hidden Windows Updates.."
            # Get the hidden Windows updates
            $hiddenUpdates = Get-WindowsUpdate -IsHidden -Verbose -Debuger -ErrorAction Stop
            $result = $hiddenUpdates
            $result | Format-Table -AutoSize
            Write-Host "Searching for Hidden Windows Updates finished"
        } catch {
            Write-Host "Failed Searching for Hidden Windows Updates"
            Write-Host "Error Message: $($_.Exception.Message)"
            Write-Host "Error Details: $($_.Exception)"
        }
    } else {
        try {
            Add-Log "Searching for Hidden Windows Updates.."
            $hiddenUpdates = Get-WindowsUpdate -MicrosoftUpdate -IsHidden -ErrorAction Stop
            Add-Log "Searching for Hidden Windows Updates finished"
        } catch {
            Add-Log "Failed searching for Hidden Windows Updates"
        }
    }

    if ($hiddenUpdates.Count -le 0) {
        Write-Host "You do not have any hidden Windows updates yet"
        Add-Log "You do not have any hidden Windows updates yet"
        return
    }

    # Create custom objects with the desired properties
    $selectedUpdates = $hiddenUpdates | ForEach-Object {
        $revNumber = $_.Identity.RevisionNumber
        $updateId =  $_.Identity.UpdateID

        [PSCustomObject]@{
            ComputerName = $_.ComputerName
            Status       = $_.Status
            KB           = $_.KBArticleID
            Size         = $_.Size
            Title        = $_.Title
            RevNumber    = $revNumber
            UpdateID     = $updateId
        }
    }

    # Display the selected updates in a GridView
    $selectedUpdates | Out-GridView -Title "Hidden Windows Updates"

    Write-Host "Show Hidden Updates finished"
    Add-Log "Show Hidden Updates finished"
}

$showHiddenUpdates = New-Object Windows.Forms.Button
$showHiddenUpdates.Text = 'Show Hidden Updates'
$showHiddenUpdates.Location = New-Object Drawing.Point(10, 370)
$showHiddenUpdates.Size = New-Object Drawing.Size(120, 35)
$showHiddenUpdates.Add_Click({
        &$showHiddenUpdatesFunc
    })

$form.Controls.Add($showHiddenUpdates)
$showHiddenUpdates.BackColor = [System.Drawing.Color]::FromArgb(30, 30, 30)
$showHiddenUpdates.ForeColor = [System.Drawing.Color]::White
$showHiddenUpdates.FlatStyle = [System.Windows.Forms.FlatStyle]::Flat
$showHiddenUpdates.FlatAppearance.BorderSize = 0
$showHiddenUpdates.FlatAppearance.MouseOverBackColor = [System.Drawing.Color]::FromArgb(62, 62, 64)
$showHiddenUpdates.FlatAppearance.MouseDownBackColor = [System.Drawing.Color]::FromArgb(27, 27, 28)
$TabPage2.Controls.Add($showHiddenUpdates)

$hideSelectedUpdatesFunc = {
    # Create a list to store the items that need to be removed
    $itemsToRemove = @()

    if ($checkedListBox.CheckedItems.Count -le 0) {
        Add-Log "No items are selected (checked)."
        Write-Host "No items are selected (checked)."
        return
    }

    foreach ($selectedUpdate in $checkedListBox.CheckedItems.GetEnumerator()) {
        $revisionNumber = $null  # Initialize or reset for each iteration
        $updateId = $null  # Initialize or reset for each iteration

        if ($updates) {
            foreach ($update in $updates) {
                if ($update.Title -eq $selectedUpdate) {
                    $revisionNumber = $update.Identity.RevisionNumber
                    $updateId = $update.Identity.UpdateID
                    break
                }
            }
        }
        else {
            #driver updates
            foreach ($driverUpdate in $driverUpdates) {
                if ($driverUpdate.Title -eq $selectedUpdate) {
                    $revisionNumber = $driverUpdate.Identity.RevisionNumber
                    $updateId = $driverUpdate.Identity.UpdateID
                    break
                }
            }
        }
        #Write-Host "RevisionNumber: $revisionNumber"
        #Write-Host "UpdateID: $updateId"

        if ($null -ne $revisionNumber -and $null -ne $updateId) {
            if ($isDebug) {
                try {
                    Write-Host 'Hiding', $selectedUpdate
                    $result = Hide-WindowsUpdate -UpdateID "$updateId" -RevisionNumber "$revisionNumber" -AcceptAll -Verbose -Debuger -ErrorAction Stop
                    $result | Format-Table -AutoSize
                    Write-Host "Hiding Selected Updates finished"
                } catch {
                    Write-Host "Failed Hiding $selectedUpdate"
                    Write-Host "Error Message: $($_.Exception.Message)"
                    Write-Host "Error Details: $($_.Exception)"
                }
            } else {
                try {
                    Add-Log "Hiding $selectedUpdate"
                    Hide-WindowsUpdate -UpdateID "$updateId" -RevisionNumber "$revisionNumber" -AcceptAll -ErrorAction Stop
                    Add-Log "Hiding Selected Updates finished"
                } catch {
                    Add-Log "Failed Hiding $selectedUpdate"
                }
            }
            
            # Add the item to the removal list after hiding it
            $itemsToRemove += $selectedUpdate
        }
    }

    # Remove the items from the CheckedListBox
    foreach ($item in $itemsToRemove) {
        $checkedListBox.Items.Remove($item)
    }
}

$hideSelectedUpdates = New-Object Windows.Forms.Button
$hideSelectedUpdates.Text = 'Hide Selected Updates'
$hideSelectedUpdates.Location = New-Object Drawing.Point(140, 370)
$hideSelectedUpdates.Size = New-Object Drawing.Size(120, 35)
$hideSelectedUpdates.Add_Click({
        &$hideSelectedUpdatesFunc
    })

$form.Controls.Add($hideSelectedUpdates)
$hideSelectedUpdates.BackColor = [System.Drawing.Color]::FromArgb(30, 30, 30)
$hideSelectedUpdates.ForeColor = [System.Drawing.Color]::White
$hideSelectedUpdates.FlatStyle = [System.Windows.Forms.FlatStyle]::Flat
$hideSelectedUpdates.FlatAppearance.BorderSize = 0
$hideSelectedUpdates.FlatAppearance.MouseOverBackColor = [System.Drawing.Color]::FromArgb(62, 62, 64)
$hideSelectedUpdates.FlatAppearance.MouseDownBackColor = [System.Drawing.Color]::FromArgb(27, 27, 28)
$TabPage2.Controls.Add($hideSelectedUpdates)

$unhideSelectedUpdatesFunc = {
    if ($isDebug) {
        try {
            Write-Host "Searching for Hidden Windows Updates.."
            # Get the hidden Windows updates
            $hiddenUpdates = Get-WindowsUpdate -IsHidden -Verbose -Debuger -ErrorAction Stop
            $result = $hiddenUpdates
            $result | Format-Table -AutoSize
        } catch {
            Write-Host "Error Message: $($_.Exception.Message)"
            Write-Host "Error Details: $($_.Exception)"
        }
    } else {
        try {
            Add-Log "Searching for Hidden Windows Updates.."
            $hiddenUpdates = Get-WindowsUpdate -MicrosoftUpdate -IsHidden -ErrorAction Stop
        } catch {
            Add-Log "Failed searching for Hidden Windows Updates"
        }
    }

    if ($hiddenUpdates.Count -le 0) {
        Add-Log "You do not have any hidden Windows updates yet"
        return
    }

    # Create custom objects with the desired properties
    $selectedUpdates = $hiddenUpdates | ForEach-Object {
        $revNumber = $_.Identity.RevisionNumber
        $updateId =  $_.Identity.UpdateID

        [PSCustomObject]@{
            ComputerName = $_.ComputerName
            Status       = $_.Status
            KB           = $_.KBArticleID
            Size         = $_.Size
            Title        = $_.Title
            RevNumber    = $revNumber
            UpdateID     = $updateId
        }
    }

    # Display the selected updates in a GridView and allow multiple selection
    $selectedUpdates = $selectedUpdates | Out-GridView -Title "Select items to unhide hidden Windows updates" -PassThru

    # Loop through each selected item and retrieve the RevNumber and UpdateID
    foreach ($selectedUpdate in $selectedUpdates) {
        $revNumber = $selectedUpdate.RevNumber
        $updateId = $selectedUpdate.UpdateID

        Write-Host "Selected Update: $($selectedUpdate.Title)"
        #Write-Host "RevNumber: $revNumber"
        #Write-Host "UpdateID: $updateId"

        if ($null -ne $revNumber -and $null -ne $updateId) {
            if ($isDebug) {
                try {
                    Write-Host 'UnHiding', $($selectedUpdate.Title)
                    $result = UnHide-WindowsUpdate -UpdateID "$updateId" -RevisionNumber "$revNumber" -AcceptAll -Verbose -Debuger -ErrorAction Stop
                    $result | Format-Table -AutoSize
                    Write-Host "UnHiding Selected Updates finished"
                } catch {
                    Write-Host "Failed UnHiding $($selectedUpdate.Title)"
                    Write-Host "Error Message: $($_.Exception.Message)"
                    Write-Host "Error Details: $($_.Exception)"
                }
            } else {
                try {
                    Add-Log "UnHiding $($selectedUpdate.Title)"
                    UnHide-WindowsUpdate -UpdateID "$updateId" -RevisionNumber "$revNumber" -AcceptAll -ErrorAction Stop
                    Add-Log "UnHiding Selected Updates finished"
                } catch {
                    Add-Log "Failed UnHiding $($selectedUpdate.Title)"
                }
            }
        }
    }
}

$unhideSelectedUpdates = New-Object Windows.Forms.Button
$unhideSelectedUpdates.Text = 'Select Updates To Unhide'
$unhideSelectedUpdates.Location = New-Object Drawing.Point(270, 370)
$unhideSelectedUpdates.Size = New-Object Drawing.Size(120, 35)
$unhideSelectedUpdates.Add_Click({
        &$unhideSelectedUpdatesFunc
    })

$form.Controls.Add($unhideSelectedUpdates)
$unhideSelectedUpdates.BackColor = [System.Drawing.Color]::FromArgb(30, 30, 30)
$unhideSelectedUpdates.ForeColor = [System.Drawing.Color]::White
$unhideSelectedUpdates.FlatStyle = [System.Windows.Forms.FlatStyle]::Flat
$unhideSelectedUpdates.FlatAppearance.BorderSize = 0
$unhideSelectedUpdates.FlatAppearance.MouseOverBackColor = [System.Drawing.Color]::FromArgb(62, 62, 64)
$unhideSelectedUpdates.FlatAppearance.MouseDownBackColor = [System.Drawing.Color]::FromArgb(27, 27, 28)
$TabPage2.Controls.Add($unhideSelectedUpdates)

$showHistoryFunc = {
    if ($isDebug) {
        try {
            Write-Host "Searching for History Windows Updates.."
            # Get the History
            $historyUpdates = Get-WUHistory -Verbose -Debuger -ErrorAction Stop
            $result = $historyUpdates
            $result | Format-Table -AutoSize
            Write-Host "Searching for History Windows Updates finished"
        } catch {
            Write-Host "Failed searching for History Windows Updates"
            Write-Host "Error Message: $($_.Exception.Message)"
            Write-Host "Error Details: $($_.Exception)"
        }
    } else {
        try {
            Add-Log "Searching for History Windows Updates.."
            $historyUpdates = Get-WUHistory -ErrorAction Stop
            Add-Log "Searching for History Windows Updates finished"
        } catch {
            Add-Log "Failed searching for History Windows Updates"
        }
    }

    # Create custom objects with the desired properties
    $selectedUpdates = $historyUpdates | ForEach-Object {

        [PSCustomObject]@{
            ComputerName = $_.ComputerName
            Result       = $_.Result
            Date           = $_.Date
            Title        = $_.Title
        }
    }

    # Display the selected updates in a GridView
    $selectedUpdates | Out-GridView -Title "History Windows Updates"

    Write-Host "Show Update History finished"
    Add-Log "Show Update History finished"
}

$showHistory = New-Object Windows.Forms.Button
$showHistory.Text = 'Show Update History'
$showHistory.Location = New-Object Drawing.Point(10, 430)
$showHistory.Size = New-Object Drawing.Size(120, 35)
$showHistory.Add_Click({
        &$showHistoryFunc
    })

$form.Controls.Add($showHistory)
$showHistory.BackColor = [System.Drawing.Color]::FromArgb(30, 30, 30)
$showHistory.ForeColor = [System.Drawing.Color]::White
$showHistory.FlatStyle = [System.Windows.Forms.FlatStyle]::Flat
$showHistory.FlatAppearance.BorderSize = 0
$showHistory.FlatAppearance.MouseOverBackColor = [System.Drawing.Color]::FromArgb(62, 62, 64)
$showHistory.FlatAppearance.MouseDownBackColor = [System.Drawing.Color]::FromArgb(27, 27, 28)
$TabPage2.Controls.Add($showHistory)

$showInstalledFunc = {
    try {
        Write-Host "Show Installed Updates"
        Add-Log "Show Installed Updates"
        # Get the installed updates with provider 'msu'
        $msuPackages = Get-Package | Where-Object { $_.ProviderName -eq "msu" } | 
            Select-Object @{Name='Name'; Expression={$_.Name}}
    
        # Get the update history from Windows Update with status 'Succeeded'
        $wuHistory = Get-WUHistory | Where-Object { $_.Result -eq 'Succeeded' } | 
            Select-Object Title, Date, @{Name='UpdateID'; Expression={$_.UpdateIdentity.UpdateID}} -ErrorAction Stop
    
        # Cross-reference by comparing the names from Get-Package and Titles from Get-WUHistory
        $updatesWithDate = foreach ($package in $msuPackages) {
            $match = $wuHistory | Where-Object { $_.Title -eq $package.Name }
            if ($match) {
                # Return an object with the Name (from Get-Package) and Date (from Get-WUHistory)
                [PSCustomObject]@{
                    Name = $package.Name
                    InstalledOn = $match.Date
                    UpdateID = $match.UpdateID
                }
            }
        }
    
        # Display the result in a GridView with a title "Installed Updates"
        $updatesWithDate | Out-GridView -Title "Installed Updates"
    
        Write-Host "Show Installed Updates finished"
        Add-Log "Show Installed Updates finished"
    } catch {
        Write-Host "Failed Showing Installed Updates"
        Add-Log "Failed Showing Installed Updates"
        Write-Host "Error Message: $($_.Exception.Message)"
        Write-Host "Error Details: $($_.Exception)"
    }
}

$showInstalled = New-Object Windows.Forms.Button
$showInstalled.Text = 'Show Installed Updates'
$showInstalled.Location = New-Object Drawing.Point(140, 430)
$showInstalled.Size = New-Object Drawing.Size(120, 35)
$showInstalled.Add_Click({
        &$showInstalledFunc
    })

$form.Controls.Add($showInstalled)
$showInstalled.BackColor = [System.Drawing.Color]::FromArgb(30, 30, 30)
$showInstalled.ForeColor = [System.Drawing.Color]::White
$showInstalled.FlatStyle = [System.Windows.Forms.FlatStyle]::Flat
$showInstalled.FlatAppearance.BorderSize = 0
$showInstalled.FlatAppearance.MouseOverBackColor = [System.Drawing.Color]::FromArgb(62, 62, 64)
$showInstalled.FlatAppearance.MouseDownBackColor = [System.Drawing.Color]::FromArgb(27, 27, 28)
$TabPage2.Controls.Add($showInstalled)

<#
$uninstallUpdateFunc = {
    # Get the installed updates with provider 'msu'
    $msuPackages = Get-Package | Where-Object { $_.ProviderName -eq "msu" } | 
        Select-Object @{Name='Name'; Expression={$_.Name}}

    # Get the update history from Windows Update with status 'Succeeded'
    $wuHistory = Get-WUHistory | Where-Object { $_.Result -eq 'Succeeded' } | 
        Select-Object Title, Date, @{Name='UpdateID'; Expression={$_.UpdateIdentity.UpdateID}}

    # Cross-reference by comparing the names from Get-Package and Titles from Get-WUHistory
    $updatesWithDetails = foreach ($package in $msuPackages) {
        $match = $wuHistory | Where-Object { $_.Title -eq $package.Name }
        if ($match) {
            # Return an object with the Name (from Get-Package), Date, and UpdateID (from Get-WUHistory)
            [PSCustomObject]@{
                Name = $package.Name
                InstalledOn = $match.Date
                UpdateID = $match.UpdateID
            }
        }
    }

    # Display the result in a GridView and allow multiple selections
    $selectedUpdates = $updatesWithDetails | Out-GridView -Title "Select To Uninstall Updates - Works only on Microsoft Windows Updates, drivers not supported at the moment." -PassThru

    # Check if any updates were selected
    if ($selectedUpdates) {
        foreach ($update in $selectedUpdates) {
            if ($isDebug) {
                try {
                    # Uninstall the selected update
                    Write-Host 'Uninstalling', $($update.Name)
                    $result = Uninstall-WindowsUpdate -UpdateID "$($update.UpdateID)" -AcceptAll -Verbose -Debuger
                    $result | Format-Table -AutoSize
                    Write-Host "Successfully uninstalled update with Name $($update.Name)"
                } catch {
                    Write-Host "Failed Uninstalling $($update.Name)"
                    Write-Host "Error Message: $($_.Exception.Message)"
                    Write-Host "Error Details: $($_.Exception)"
                }
            } else {
                try {
                    Add-Log "Uninstalling $($update.Name)"
                    Uninstall-WindowsUpdate -UpdateID "$($update.UpdateID)" -AcceptAll
                    Add-Log "Successfully uninstalled update with Name $($update.Name)"
                } catch {
                    Add-Log "Failed Uninstalling $($update.Name)"
                }
            }
        }
    } else {
        Write-Host "No updates selected for uninstallation."
        Add-Log "No updates selected for uninstallation."
    }

    Write-Host "Show Installed Updates finished"
    Add-Log "Show Installed Updates finished" 
}

$uninstallUpdate = New-Object Windows.Forms.Button
$uninstallUpdate.Text = 'Select Updates To Uninstall'
$uninstallUpdate.Location = New-Object Drawing.Point(270, 430)
$uninstallUpdate.Size = New-Object Drawing.Size(120, 35)
$uninstallUpdate.Add_Click({
        &$uninstallUpdateFunc
    })

$form.Controls.Add($uninstallUpdate)
$uninstallUpdate.BackColor = [System.Drawing.Color]::FromArgb(30, 30, 30)
$uninstallUpdate.ForeColor = [System.Drawing.Color]::White
$uninstallUpdate.FlatStyle = [System.Windows.Forms.FlatStyle]::Flat
$uninstallUpdate.FlatAppearance.BorderSize = 0
$uninstallUpdate.FlatAppearance.MouseOverBackColor = [System.Drawing.Color]::FromArgb(62, 62, 64)
$uninstallUpdate.FlatAppearance.MouseDownBackColor = [System.Drawing.Color]::FromArgb(27, 27, 28)
$TabPage2.Controls.Add($uninstallUpdate)
#>

$showDriver = {
    if ($showOnlyDriver.Checked) {
        Write-Host "Show Only Driver Updates.."
        Add-Log "Show Only Driver Updates.."
        $noDriverUpdates.Visible = $false
        $noUpdates.Visible = $false
        
        $checkedListBox.Items.Clear()
        $checkingUpdatesDriver.Visible = $true
        $form.Refresh()

        if ($isDebug) {
            try {
                Write-Host "Searching for Windows Driver Updates"
                $Global:driverUpdates = Get-WindowsUpdate -MicrosoftUpdate -UpdateType Driver -Verbose -Debuger -ErrorAction Stop
                $result = $Global:driverUpdates
                $result | Format-Table -AutoSize
                Write-Host "Searching for Windows Driver Updates finished"
            } catch {
                Write-Host "Failed Searching for Windows Driver Updates"
                Write-Host "Error Message: $($_.Exception.Message)"
                Write-Host "Error Details: $($_.Exception)"
            }
        } else {
            try {
                Add-Log "Searching for Windows Driver Updates"
                $Global:driverUpdates = Get-WindowsUpdate -MicrosoftUpdate -UpdateType Driver -ErrorAction Stop
                Add-Log "Searching for Windows Driver Updates finished"
            } catch {
                Add-Log "Failed searching for Windows Driver Updates"
            }
        }
        if (!$driverUpdates) {
            $noDriverUpdates.Visible = $true
        } 
        foreach ($driverUpdate in $driverUpdates) {
            $checkedListBox.Items.Add($driverUpdate.Title, $false)
        }
        #show scroll bar if there is more than 7 updates
        if ($checkedListBox.Items.Count -gt 7) {
            $checkedListBox.ScrollAlwaysVisible = $true
        }

        $checkingUpdatesDriver.Visible = $false
    }
    else {
        $noDriverUpdates.Visible = $false
        if ($updates) {
            $checkedListBox.Items.Clear()
            foreach ($update in $updates) {
                $checkedListBox.Items.Add($update.Title, $false)
            }
        }
    }
}

$showOnlyDriver = New-Object System.Windows.Forms.CheckBox
$showOnlyDriver.Location = New-Object System.Drawing.Point(250, 170)
$showOnlyDriver.Size = New-Object System.Drawing.Size(170, 20)
$showOnlyDriver.ForeColor = 'White'
$showOnlyDriver.Text = 'Show Only Driver Updates'
$showOnlyDriver.add_CheckedChanged($showDriver)
$TabPage2.Controls.Add($showOnlyDriver)

# Boolean flag to ensure the code runs only once
$codeExecuted = $false

# Event handler for Shown event to execute code after the form is fully visible
$form.Add_Shown({
    if (-not $codeExecuted) {
        # Code to execute after the form has fully loaded and is shown
        $apiVersion = (Get-WUApiVersion).ApiVersion
        $wuApiDllVersion = (Get-WUApiVersion).WuapiDllVersion
        $psWindowsUpdate = (Get-WUApiVersion).PSWindowsUpdate
        $psWUModuleDll = (Get-WUApiVersion).PSWUModuleDll
        Write-Host "Windows Update Agent API version: $($apiVersion) ($($wuApiDllVersion))"
        Add-Log "Windows Update Agent API version: $($apiVersion) ($($wuApiDllVersion))"
        Write-Host "PSWindowsUpdate version: ($($psWindowsUpdate))"
        Add-Log "PSWindowsUpdate version: ($($psWindowsUpdate))"
        Write-Host "PSWUModuleDll version: ($($psWUModuleDll))"
        Add-Log "PSWUModuleDll version: ($($psWUModuleDll))"

        #check update server
        $server = getWUServer
        $serverConnect = getWUConnection
        if ($null -ne $server -or $serverConnect) {
            #enable connection so that get-windowsupdate works
            Write-host 'Connect to Windows Update Location Disabled..'
            Add-Log "Connect to Windows Update Location Disabled.."
            Write-Host 'Enabling Connection'
            Add-Log "Enabling Connection"
            Reg.exe delete 'HKLM\SOFTWARE\Policies\Microsoft\Windows\WindowsUpdate' /v 'DoNotConnectToWindowsUpdateInternetLocations' /f >$null 2>&1
            Reg.exe delete 'HKLM\SOFTWARE\Policies\Microsoft\Windows\WindowsUpdate' /v 'WUServer' /f >$null 2>&1
            Reg.exe delete 'HKLM\SOFTWARE\Policies\Microsoft\Windows\WindowsUpdate' /v 'WUStatusServer' /f >$null 2>&1
            Reg.exe delete 'HKLM\SOFTWARE\Policies\Microsoft\Windows\WindowsUpdate' /v 'UpdateServiceUrlAlternate' /f >$null 2>&1
        }

        # Set the flag to true to prevent re-execution
        $codeExecuted = $true

        $form.Activate()
    }
})

# Run the form
[System.Windows.Forms.Application]::Run($form)

# execute code after the form is closed
if ($null -ne $server -or $serverConnect) {
    Write-Host "Form has been closed!"
    Write-Host 'Disabling Windows Update Location Connectivity'
    Reg.exe add 'HKLM\SOFTWARE\Policies\Microsoft\Windows\WindowsUpdate' /v 'WUServer' /t REG_SZ /d 'https://DoNotUpdateWindows10.com/' /f
    Reg.exe add 'HKLM\SOFTWARE\Policies\Microsoft\Windows\WindowsUpdate' /v 'WUStatusServer' /t REG_SZ /d 'https://DoNotUpdateWindows10.com/' /f
    Reg.exe add 'HKLM\SOFTWARE\Policies\Microsoft\Windows\WindowsUpdate' /v 'UpdateServiceUrlAlternate' /t REG_SZ /d 'https://DoNotUpdateWindows10.com/' /f
    Reg.exe add 'HKLM\SOFTWARE\Policies\Microsoft\Windows\WindowsUpdate' /v 'DoNotConnectToWindowsUpdateInternetLocations' /t REG_DWORD /d '1' /f 
}

$stream.Dispose()
$form.Dispose()
if ($form2) {
    $form2.Dispose()
}

exit
