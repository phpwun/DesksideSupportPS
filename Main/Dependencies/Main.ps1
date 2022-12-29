#DesksideSupportPS
    #10/12/22
    #HA Deskside Support
    #Bruh
        #Use the DCU finder function to look for teams agnostic of current user

#Global Variables
    #Identifies if the device is #64 Bit or #32 Bit
    $Architecture = Get-WmiObject -Class Win32_OperatingSystem | Select-Object OSArchitecture

#Global Functions
    #Accepts file input
      function AcceptFile($type, $where) {
        Add-Type -AssemblyName System.Windows.Forms
        $FileBrowser = New-Object System.Windows.Forms.OpenFileDialog -Property @{
        InitialDirectory = [Environment]::GetFolderPath($where)
        Filter = $type
        }
    $null = $FileBrowser.ShowDialog()
    return $FileBrowser.FileName
    }

#Component Functions
    #Installs Google Chrome
    function GoogleChrome{
        $FolderName = "C:\Program Files\Google\Chrome\Application\"
        if (Test-Path $FolderName) {
            Write-Host "Chrome is already installed."
        }
        else
        {
        Write-Host "Installing Chrome."
            Start-Sleep 1
        $LocalTempDir = $env:TEMP; $ChromeInstaller = "ChromeInstaller.exe"; (new-object System.Net.WebClient).DownloadFile('http://dl.google.com/chrome/install/375.126/chrome_installer.exe', "$LocalTempDir\$ChromeInstaller"); & "$LocalTempDir\$ChromeInstaller" /silent /install; $Process2Monitor =  "ChromeInstaller"; Do { $ProcessesFound = Get-Process | Where-Object{$Process2Monitor -contains $_.Name} | Select-Object -ExpandProperty Name; If ($ProcessesFound) { "Still running: $($ProcessesFound -join ', ')" | Write-Host; Start-Sleep -Seconds 2 } else { Remove-Item "$LocalTempDir\$ChromeInstaller" -ErrorAction SilentlyContinue -Verbose } } Until (!$ProcessesFound)
            Write-Output "Finished Chrome Intallation."
                Start-Sleep 1
        }
    }

    #Installs / Initiates Dell Command Update
        function DellCommandUpdate($SubFunction, $Bypass = $false) {
            if ($SubFunction -eq "Prepare") {
            #Downloads and Installs Dell Command Update
                function DCUOne {
                    #- Install DCU before running
                        Copy-Item -Path "C:\Users\haitadmin\Downloads\DesksideSupportPS-main\Main\Dependencies\DCU.exe" -Destination "C:\temp"
                            Write-Host "Attempting DCU Install."
                                Start-Sleep 1
                        & "C:\temp\DCU.exe"
                            Write-Host "Finished Installing DCU."
                                Start-Sleep 1
                }
                DCUOne
            } elseif ($SubFunction -eq "Start") {
            #Locates and initiates Dell Command Update
                function DCUTwo ($OVRDell) {
                    #Find DCU Architechture
                        If ($Architecture.OSArchitecture -eq "32-bit" -Or $OVRDell -eq "true") {
                                $File = Get-ChildItem -Path $env:ProgramFiles -Filter "dcu-cli.exe" -ErrorAction SilentlyContinue -Recurse
                            } else {
                                $File = Get-ChildItem -Path ${env:ProgramFiles(x86)} -Filter "dcu-cli.exe" -ErrorAction SilentlyContinue -Recurse
                            }
                    #Initiate the Update
                        Write-Host $File.FullName
                            Write-Host "Attempting DCU Launch"
                                Start-Sleep 1
                                Start-Sleep 1
                                    #$a=$File.FullName
                                    & "C:\Program Files\Dell\CommandUpdate\dcu-cli.exe" /configure silent '-autoSuspendBitLocker=enable -userConsent=disable'
                                    & "C:\Program Files\Dell\CommandUpdate\dcu-cli.exe" /scan -outputLog='C:\dell\logs\scan.log'
                                    & "C:\Program Files\Dell\CommandUpdate\dcu-cli.exe" /applyUpdates -outputLog='C:\dell\logs\applyUpdates.log'
                                Write-Host "DCU Finished."
                                    Start-Sleep 1
                    }
                    DCUTwo $Bypass
                }
        }

    #Initiates Bitlocker Drive Encryption
        function Bitlocker($SubFunction){
            if ($SubFunction -eq "Prepare") {
            #Removes an old bitlocker file to allow the main function to work
                function BitlockerOne{
                    $ReAgent = "C:\Windows\System32\Recovery\ReAgent.xml"
                    if (Test-Path $ReAgent) {
                        Remove-Item $ReAgent -Force -Confirm:$false
                            Write-host "$ReAgent has been deleted"
                                Start-Sleep 1
                    }
                    else {
                        Write-host "$ReAgent doesn't exist, it will be skipped."
                            Start-Sleep 1
                    }
                }
                BitlockerOne
            } elseif ($SubFunction -eq "Start") {
            #Initiates the Bitlocker Encryption of the Device
                function BitlockerTwo{
                    Write-Host "Attempting Bitlocker2, this will prompt you for a pin "4357""
                        Start-Sleep 1
                        $Pin = ConvertTo-SecureString "4357" -AsPlainText -Force
                            Enable-BitLocker -MountPoint "C:" -UsedSpaceOnly -SkipHardwareTest -Pin $Pin -AdAccountOrGroupProtector
                            Get-BitLockerVolume -MountPoint "C:"
                            Write-Host "Bitlocker2 Finished."
                            Start-Sleep 1
                }
                BitlockerTwo
            }
        }

    #Installs WindowsUpdate for PS and Initiates Windows Update
        function WinUpdate($SubFunction){
            if ($SubFunction -eq "Prepare") {
            #Windows Update Module Install
                function WinUpdateOne {
                    Write-Host "Attempting WinUpdatePSModule."
                        Start-Sleep 2
                    Install-PackageProvider -Name NuGet -Force
                    Set-PSRepository -Name PSGallery -InstallationPolicy Trusted
                    Install-Module -Name PSWindowsUpdate -Force
                        Write-Host "Installing WinUpdatePSModule."
                            Start-Sleep 2
                }
                WinUpdateOne
            } elseif ($SubFunction -eq "Start") {
            #Begins the Actual Install of the Updates
                function WinUpdateTwo {
                    #Initiates Package and Checks for Updates
                        Get-Package -Name PSWindowsUpdate -Force
                        Get-WindowsUpdate -ForceInstall
                            Write-Host "Starting WinUpdate."
                                Start-Sleep 2
                    #I dont remeber why this flag is here, but the rest just starts the update
                        #Add-WUServiceManager -ServiceID "7971f918-a847-4430-9279-4a52d1efe18d" -AddServiceFlag 7
                        Add-WUServiceManager -ServiceID 7971f918-a847-4430-9279-4a52d1efe18d -Confirm:$false
                        #Get-WUlist -MicrosoftUpdate
                            Write-Host 'Initiating WinUpdate.'
                                Start-Sleep 2
                    Set-PSRepository -Name PSGallery -InstallationPolicy Trusted
                    Install-WindowsUpdate -MicrosoftUpdate -Confirm:$False -ForceInstall -AcceptAll -IgnoreReboot
                            Write-Host "Finishing WinUpdate."
                                Start-Sleep 2
                }
                WinUpdateTwo
            }
        }

    #Initiates Device Rename and Domain Addition
        function DomainAddition ($Creds) {
            #Adding the Renamed Device to the Domain
                Write-Host "Attempting Domain Add."
                    Start-Sleep 2
                $SerialName = (Get-WmiObject -class win32_bios).SerialNumber
                if ($env:computername -eq $SerialName) {
                    Write-Host "Device is Already: $SerialName"
                } else {
                    Write-Host "Old: "
                        Write-Host $SerialName
                        Write-Host $env:computername
                            Rename-Computer $SerialName
                    Write-Host "New: "
                        Write-Host $SerialName
                        Write-Host $env:computername
                    Add-Computer -DomainName "cho.ha.local" -Credential $Creds -Force -Options JoinWithNewName,accountcreate
                        Write-Host "Added to Domain."
                            Start-Sleep 2
                }
            }

    #Installs the Automate Agent
        function AutomateAgent{
            Write-Host "Attempting Automate Install."
            Copy-Item -Path "C:\Users\haitadmin\Downloads\DesksideSupportPS-main\Main\Dependencies\Agent.msi" -Destination "C:\temp"
                Start-Sleep 2
            #Start-Process -Wait -FilePath "C:\temp\Agent.msi" -ArgumentList "/P" -PassThru
            msiexec.exe /a "C:\temp\Agent.msi"  /passive
                Write-Host "Agent Installer Finished."
                    Start-Sleep 2
        }

    #Installs the SentinalOne Agent
        function S1Agent{
            Copy-Item -Path "C:\Users\haitadmin\Downloads\DesksideSupportPS-main\Main\Dependencies\S1.exe" -Destination "C:\temp"
            Copy-Item -Path "C:\Users\haitadmin\Downloads\DesksideSupportPS-main\Main\Dependencies\S1.bat" -Destination "C:\temp"
            Write-Host "Attempting S1 Install."
                Start-Sleep 1
            & cmd.exe /c C:\temp\S1.bat
            #Start-Process -Wait -FilePath "C:\temp\S1.exe" -ArgumentList "/passive" " -PassThru
                Write-Host "Finished Installing DCU."
                    Start-Sleep 1
        }

    #Core Functions
        #Sweeps through all Windows Users and Clear's Non-Esentiall Ones
            function RoutineClearMain {
                $ErrorActionPreference='silentlycontinue'
                $path = 'C:\Users'
                $excluded = 'haitadmin','Public','Onward','Administrator'
                    Get-ChildItem $path -Exclude $excluded -Include *.* -Recurse -Force | ForEach-Object  { $_.Delete()}
                    Get-ChildItem $path -Exclude $excluded -Force | ForEach-Object   { $_.Delete()}
                    Get-ChildItem $path
                Read-Host -Prompt "Done."
            }

    #Sets things up post re-imaging
        function PostImageMain($SubFunction){
        $SubFunction = Read-Host "Prepare [Pre-Restart] (1) or Start [Post-Restart] (2)"
            if ($SubFunction -eq "1") {
                function PostImageOne { #Pre-Restart
                    GoogleChrome
                    DellCommandUpdate "Start" $true
                    Bitlocker "Prepare"
                    WinUpdate "Prepare"
                        WinUpdate "Start"
                    DomainAddition $Credential
                    Write-Host "Restarting.."
                        Start-Sleep 2
                            Write-Host "Restart when done."
                            #Restart-Computer
                }
                PostImageOne
            } elseif ($SubFunction -eq "2") { #Post-Restart
                function PostImageTwo {
                    DomainAddition $Credential
                        Bitlocker "Start"
                    AutomateAgent
                    Write-Host "Enable Bitlocker After Restart."
                        Write-Host "Restarting.."
                            Start-Sleep 2
                                Write-Host "Restart when done."
                                #Restart-Computer
                }
                PostImageTwo
            }

    }

    #Assigns a csv list of service tags to the HA Laptops OU (Needs to be changed to be a modular OU)
        function ADOUChangeMain{
            $Where = Read-Host "Please Enter OU Path: (HA, HAI, HH, HHCS, HHO)"
            $What = Read-Host "Please Enter Device List Type: (Laptops, Desktops)"
            $filety = 'Comma Seperated Values (*.csv)|*.csv'; $location = 'Desktop'; $File = AcceptFile $filety $location
            $laptops = Get-Content $File
                    foreach ($laptop in $laptops) {
                        $obj = Get-ADComputer $laptop
                        Get-ADComputer $obj | Move-ADObject -TargetPath "OU=$What,OU=$Where,OU=Heartland Alliance,OU=Systems,DC=cho,DC=ha,DC=local" -Verbose
                    }
        }

    #Sets up new devices out of box
        function NewDeviceMain {
            $SubFunction = Read-Host "Prepare [Pre-Restart] (1) or Start [Post-Restart] (2)" #"Depreciated, Only one Run Needed"
            if ($SubFunction -eq "1") {
                function NewDeviceOne {
                    DellCommandUpdate "Prepare"
                        #DellCommandUpdate "Start"
                    WinUpdate "Prepare"
                        #WinUpdate "Start"
                      Start-Sleep 2
                    S1Agent
                        Write-Host "Restart when done."
                        #Restart-Computer
                }
                NewDeviceOne
            } elseif ($SubFunction -eq "2") { #Post-Restart
                function NewDeviceTwo {
                    WinUpdate "Start"
                    DellCommandUpdate "Start"
                      Start-Sleep 2
                    S1Agent
                    Write-Host "Restart when done."
                    #Restart-Computer
                }
                NewDeviceTwo
            }
        }

        function ApplicationFinders($SubFunction, $listorvariable) {
            if ($SubFunction -eq "Main") {
                foreach ($software in $listorvariable)
                {
                    $installed = $null -ne (Get-ItemProperty HKLM:\Software\Microsoft\Windows\CurrentVersion\Uninstall\* | Where-Object { $_.DisplayName -Match $software })
                    If(-Not $installed) {
                        Write-Host "'$software' NOT is installed."
                    }else {
                        Write-Host "'$software' is installed."
                    }
                }
            } elseif ($SubFunction -eq "Sub") {
                foreach ($Item in $listorvariable)
                {
                    If (Test-Path $Item) {
                        Write-Output "'$Item' is installed."
                    } Else {
                        Write-Output "'$Item' NOT is installed."
                    }
                }
            } elseif ($SubFunction -eq "SubTwo"){
                function finddellarch($OVRDell = $false){
                    $Architecture = Get-WmiObject -Class Win32_OperatingSystem | Select-Object OSArchitecture
                    If ($Architecture.OSArchitecture -eq "32-bit" -Or $OVRDell -eq "true") {
                        $File = Get-ChildItem -Path $env:ProgramFiles -Filter "dcu-cli.exe" -ErrorAction SilentlyContinue -Recurse
                            Write-Host $File.FullName " is installed."
                    } else {
                        $File = Get-ChildItem -Path ${env:ProgramFiles(x86)} -Filter "dcu-cli.exe" -ErrorAction SilentlyContinue -Recurse
                            Write-Host $File.FullName " is installed."
                    }
                }
                finddellarch($listorvariable)
            }
        }

        function CheckListHA {
            ApplicationFinders "Main" "Office",
                "Sentinel Agent",
                "Office@Hand",
                "Citrix",
                "Forticlient",
                "DisplayLink",
                "Chrome"
            ApplicationFinders "Sub" "$env:WINDIR\LTSvc\",
                "$env:APPDATA\Microsoft\Teams\",
                "C:\Program Files (x86)\Adobe\Acrobat Reader DC\Reader\AcroRd32.exe"
            ApplicationFinders "SubTwo" $true
        }
#Main Menu Loop
    function Show-Menu {
        Write-Host "
        Deskside Support Options:

        1:
            Cluttered Devices
                (Clears Non-Admin Users, DiskCleanup, DeFrag)

        2:
            Post-Imaged Devices
                (Bitlocker and Agent Install, After Reboot
                Automate > Scripts > AntiVirus
                S1 Deploy New)

        3:
            Mover of Devices
                (Move AD Users en mass)

        4:
            New Devices
                (Out of Box Configuration,
                Automate > Scripts > AntiVirus
                S1 Deploy New)

        5:
            Checklist
                (Run after a user has logged in and finished setting things up)

        E:
        Exit Script."
    }

    #WinUpdateOne
    #Start-Sleep 2
    #DomainAddition

    do {
        Show-Menu
        $UserInput = Read-Host
        switch ($UserInput)
        {
            '1' {
                    RoutineClearMain
                }
            '2' {
                    PostImageMain
                }
            '3' {
                    ADOUChangeMain
                }
            '4' {
                    NewDeviceMain
                }
            '5' {
                    CheckListHA
                }
            'e' {
                    return
                }
        }
        pause
    }
    until ($input -eq 'e')