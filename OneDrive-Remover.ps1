$32_uninstall_bin = "$($env:SystemRoot)\System32\OneDriveSetup.exe"
$64_uninstall_bin = "$($env:SystemRoot)\SysWOW64\OneDriveSetup.exe"

$is_64 = (Test-Path $64_uninstall_bin)


function get_location_paths() {

    $locations = [System.Collections.ArrayList]::new()
    
    $known = @(
        "$($env:USERPROFILE)\OneDrive", `
            "$($env:LOCALAPPDATA)\Microsoft\OneDrive", `
            "$($env:ProgramData)\Microsoft\OneDrive", `
            "$($env:SystemDrive)\OneDrivetemp", `
            "$($env:LOCALAPPDATA)\Microsoft\OneDriveSetup.exe"
    )
    
    $paths = @(
        (Get-ChildItem ($env:SystemRoot + "\WinSxS") |
        Where-Object -FilterScript { $_.Name -Like "*OneDrive*" }).FullName,

        (Get-ChildItem ($env:SystemRoot + "\servicing\Packages\") |
        Where-Object -FilterScript { $_.Name -Like "*OneDrive*" }).FullName,

        (Get-ChildItem ($env:SystemRoot + "\WinSxS\Manifests\") |
        Where-Object -FilterScript { $_.Name -Like "*onedrive*" }).FullName,

        (Get-ChildItem ($env:SystemRoot + "\System32") |
        Where-Object -FilterScript { $_.Name -Like "*onedrive*" }).FullName
    )

    $null = foreach ($L in $paths) {
        $null = foreach ($i in $L) {
            if (Test-Path $i) {
                $locations.Add($i.ToString())
            }
        }
    }

    $null = foreach ($i in $known) {
        if (Test-Path $i) {
            $locations.Add($i)
        }
    }

    if ($is_64) {
        $locations.Add($64_uninstall_bin)
    }
    else {
        $locations.Add($32_uninstall_bin)
    }

    return $locations
}

function main() {
    
    # check if ran with administrator privs
    $is_admin = [bool](([System.Security.Principal.WindowsIdentity]::GetCurrent()).groups -match "S-1-5-32-544")

    if (!$is_admin) {
        Write-Host "This Script must be ran as administrator!"
        return
    }


    $paths = get_location_paths

    # try 5 times to kill process
    $killed = $False
    for ($i = 0; $i -lt 5; $i++) {
        $proc = Get-Process | Where-Object -FilterScript { $_.Name -like "*onedrive*" } | Stop-Process -Force

        Write-Host "[*] Killing One Drive Process: Try #$($i + 1)"

        if (!$proc) {
            Write-Host "[+] Killed Succesfully"
            $killed = $True
            break
        }
        else {
            Start-Sleep 1
        }
    }

    if (!$Killed) {
        Write-Host "[-] Could not kill OneDrive try killing the process manualy"
        return
    }

    # run /uninstall on OneDriveSetup.exe
    Write-Host "[*] running `"OneDriveSetup.exe /uninstall`""
    try {
        if ($is_64) {
            $null = Invoke-Expression "$($64_uninstall_bin) /uninstall" | Out-Null
        }
        else {
            $null = Invoke-Expression "$($32_uninstall_bin) /uninstall" | Out-Null
        }

    }
    catch [System.Management.Automation.CommandNotFoundException] {
        Write-Warning "OneDriveSetup.exe doesn't exist"
    }

    $keys = @(
        "HKEY_CLASSES_ROOT\AppID\OneDrive.EXE",
        "HKEY_CLASSES_ROOT\CLSID\{018D5C66-4533-4307-9B53-224DE2ED1FE6}",
        "HKEY_CLASSES_ROOT\Wow6432Node\CLSID\{018D5C66-4533-4307-9B53-224DE2ED1FE6}"
    )
    
    # remove registry keys
    Write-Host "[*] removing regisry keys"
    $null = foreach ($i in $keys) {
        $null = Invoke-Expression "cmd.exe /C 'REG Delete /f `"$($i)`" 2>nul'"
    }

    # remove files and folders
    Write-Host "[*] removing files and folders"
    
    # change ownership to user
    # change permsissions to full for Users group
    $null = foreach ($i in ($paths | Select-Object -Skip 1)) {
        
        try {
            $item = Get-Item -LiteralPath $i
        }
        catch { continue }
        
        if (Test-Path $item) {
            if ($item.Attributes -eq "Directory") {
                $null = Invoke-Expression "cmd.exe /C 'takeown.exe /R /F `"$($i)`" 1>null'"
            }
            else {
                $null = Invoke-Expression "cmd.exe /C 'takeown.exe /F `"$($i)`" 2>null'"
            }
        }

        $null = Invoke-Expression "cmd.exe /C 'icacls.exe `"$($i)`" /grant Users:(F) /T /C /Q'"
    }


    # delete all items
    $null = foreach ($i in $paths) {
        try {
            if ($i -ne 0) {
                $item = Get-Item -LiteralPath $i
            }
        }
        catch {continue}

        #     Invoke-Expression "cmd.exe /C 'rmdir /S /Q `"$($i)`"'"
        Invoke-Expression "cmd.exe /C 'del /S /F /Q $($i)'"
    }
}

main