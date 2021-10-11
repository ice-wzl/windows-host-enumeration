Function hostenum {
    Write-Output "
     ▄▀▀█▀▄    ▄▀▄▄▄▄   ▄▀▀█▄▄▄▄  ▄▀▀▄    ▄▀▀▄  ▄▀▀▀▀▄   ▄▀▀▀▀▄     
    █   █  █  █ █    ▌ ▐  ▄▀   ▐ █   █    ▐  █ █     ▄▀ █    █      
    ▐   █  ▐  ▐ █        █▄▄▄▄▄  ▐  █        █ ▐ ▄▄▀▀   ▐    █      
        █       █        █    ▌    █   ▄    █    █          █       
     ▄▀▀▀▀▀▄   ▄▀▄▄▄▄▀  ▄▀▄▄▄▄      ▀▄▀ ▀▄ ▄▀     ▀▄▄▄▄▀  ▄▀▄▄▄▄▄▄▀ 
    █       █ █     ▐   █    ▐            ▀           ▐   █         
    ▐       ▐ ▐         ▐                                 ▐         
    " 
    Write-Output "Windows Host Enumeration" 

    #start survey
    #date
    Write-Output "Date: "
    Write-Output "============================="
    Get-Date

    #time zone info
    Write-Output "Host TimeZone: "
    Write-Output "============================="
    Get-Item HKLM:\System\CurrentControlSet\Control\TimeZoneInformation | findstr /i TimeZoneKeyName

    #current ip address
    Write-Output "Ip Address: "
    Write-Output "============================="
    Get-WmiObject -Class win32_networkadapterconfiguration | Where-Object {$_.IPAddress}

    #current pid for script...helps to know when its time to deal with logs
    Write-Output "Current Process Id: "
    Write-Output "============================="
    $PID

    #current user check
    Write-Output "User running the script: "
    Write-Output "============================="
    ([Security.Principal.WindowsIdentity]::GetCurrent()).Name

    #admin rights check
    Write-Output "Currently have Administrator rights: "
    Write-Output "============================="
    ([Security.Principal.WindowsPrincipal][Security.Principal.WindowsIdentity]::GetCurrent()).IsInRole([Security.Principal.WindowsBuiltInRole] "Administrator")

    #starting security check section
    Write-Output "Security Checks"
    Write-Output "============================="

    #vm checks
    Write-Output "Are we in a VM: "
    Write-Output "============================="
    #bios --> will help tell if we are in a VM
    Get-Item HKLM:\HARDWARE\DESCRIPTION\System\BIOS
    #process list check for virtualization software running --> will only find quemu, vmware, virtualbox
    Get-Process | select ProcessName, Id | findstr /i "vm"
    Get-Process | select ProcessName, Id | findstr /i "virtual"
    Get-Process | select ProcessName, Id | findstr /i "quemu"
    Get-Process | select ProcessName, Id | findstr /i "vbox"

    #process list enumeration
    Write-Output "Process List Enumeration: "
    Write-Output "============================="
    tasklist
    Get-Process | select ProcessName, Id, Path

    #service enumeration for both running and stopped will be in 2 different lists
    Write-Output "Service List Enumeration: "
    Write-Output "============================="
    Get-Service | Where-Object {$_.Status -eq "Running"}
    Get-Service | Where-Object {$_.Status -eq "Stopped"}

    #default shell, legal banner
    Write-Output "Default Shell: "
    Write-Output "============================="
    Get-Item 'HKLM:\Software\Microsoft\Windows NT\CurrentVersion\Winlogon' | findstr "Shell"
    Write-Output "Legal Banner Check: "
    Write-Output "============================="
    Get-Item 'HKLM:\Software\Microsoft\Windows NT\CurrentVersion\Winlogon' | findstr "LegalNoticeText"
    Get-Item 'HKLM:\Software\Microsoft\Windows NT\CurrentVersion\Winlogon' | findstr "LegalNoticeCaption"
    
    Write-Output "Networks this host has connected to: "
    Write-Output "============================="
    Get-ChildItem 'HKLM:\Software\Microsoft\Windows NT\CurrentVersion\NetworkList\Profiles' | findstr /i Profilename

    #firewall check
    Write-Output "Checking Firewall Status: "
    Write-Output "============================="
    get-service | findstr /i "mpssvc"

    #defender checks
    Write-Output "Windows Defender Checks: "
    Write-Output "============================="
    Get-Service | findstr /i "WinDefend"
    Get-Process | select ProcessName, Id | findstr /i "MsMpEng" 

    Write-Output "Defenders Directory: "
    Write-Output "============================="
    Get-Item HKLM:\SYSTEM\CurrentControlSet\Services\WinDefend | findstr /i "ImagePath"

    #logging status check
    Write-Output "Host Logging Status: "
    Write-Output "============================="
    Get-LogProperties Security | select enabeled
    auditpol /get /category:*

    #starting system information enumeration
    Write-Output "System Information"
    Write-Output "============================="
    Write-Output "Operating System Information: "
    Start-Sleep -s 3
    Get-ComputerInfo
    Start-Sleep -s 1

    #hiberfil.sys check
    Write-Output "hiberfil.sys check: "
    Write-Output "============================="
    Get-ChildItem -Force C:\ | findstr /i hiberfil.sys 

    #drive enumeration
    Write-Output "Drive Enumeration: "
    Write-Output "============================="
    Get-WmiObject -Class win32_logicaldisk -Filter 'DriveType=3' | Format-Table DeviceId, Size, FreeSpace
    fsutil fsinfo drives
    Get-PSDrive

    #interfaces on box 
    Write-Output "Interfaces: "
    Write-Output "============================="
    ipconfig /all

    #network connections
    Write-Output "Network Connections with process: "
    Write-Output "============================="
    netstat -bano

    #checking userinit.exe persistance
    Write-Output "userinit.exe Persistance Checks"
    Write-Output "============================="
    Get-Item 'HKLM:\Software\Microsoft\Windows NT\CurrentVersion\Winlogon' | findstr "Userinit"

    #persistance checks, time to find the malwares
    Write-Output "Persistance Checks"
    Write-Output "============================="
    Write-Output "Registry"
    Write-Output "============================="
    Write-Output "Run/RunOnce Keys: "
    Write-Output "============================="
    Get-Item HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Run 
    Get-Item HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\RunOnce 
    Get-Item HKCU:\SOFTWARE\Microsoft\Windows\CurrentVersion\Run 
    Get-Item HKCU:\SOFTWARE\Microsoft\Windows\CurrentVersion\RunOnce 
    
    #writing completion date
    Write-Output "Script Completion Date & Time"
    Write-Output "============================="
    Get-Date
} 
hostenum > C:\Windows\Temp\win-host-enum.txt
Write-Output "Script is complete, check C:\Windows\Temp\win-host-enum.txt for output."


































