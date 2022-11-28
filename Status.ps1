
$ids = @()
$mode = @()

(Get-MpPreference).AttackSurfaceReductionRules_Ids | foreach-object { $ids += $_ }
(Get-MpPreference).AttackSurfaceReductionRules_Actions | foreach-object { $mode += $_ } 
Write-Host "Test"
#$ids
#$mode

 function ASRStatus {
    #$mode
    #$ids
    $v = 0
    foreach ($id in $ids) {
        if ($id -eq "56a863a9-875e-4185-98a7-b882c64b5ce5") {
            Write-Host "# Block abuse of exploited vulnerable signed drivers" -ForegroundColor Green
            if ($mode[$v] -eq 0){
                Write-Host "Not Configured or Disabled" -ForegroundColor DarkRed
                $v += 1
            }
            elseif ($mode[$v] -eq 1){
                Write-Host "Blocked" -ForegroundColor Red
                $v += 1
            }
            elseif ($mode[$v] -eq 2){
                Write-Host "Audit Mode" -ForegroundColor Magenta
                $v += 1
            }
            elseif ($mode[$v] -eq 6){
                Write-Host "Warn" -ForegroundColor Yellow
                $v +=1
            }

        }

        if ($id -eq "7674ba52-37eb-4a4f-a9a1-f0f9a1619a2c") {
            Write-Host "# Block Adobe Reader from creating child processes" -ForegroundColor Green
            if ($mode[$v] -eq 0){
                Write-Host "Not Configured or Disabled" -ForegroundColor DarkRed
                $v += 1
            }
            elseif ($mode[$v] -eq 1){
                Write-Host "Blocked" -ForegroundColor Red
                $v += 1
            }
            elseif ($mode[$v] -eq 2){
                Write-Host "Audit Mode" -ForegroundColor Magenta
                $v += 1
            }
            elseif ($mode[$v] -eq 6){
                Write-Host "Warn" -ForegroundColor Yellow
                $v +=1
            }

        }

        if ($id -eq "d4f940ab-401b-4efc-aadc-ad5f3c50688a") {
            Write-Host "# Block all Office applications from creating child processes" -ForegroundColor Green
            if ($mode[$v] -eq 0){
                Write-Host "Not Configured or Disabled" -ForegroundColor DarkRed
                $v += 1
            }
            elseif ($mode[$v] -eq 1){
                Write-Host "Blocked" -ForegroundColor Red
                $v += 1
            }
            elseif ($mode[$v] -eq 2){
                Write-Host "Audit Mode" -ForegroundColor Magenta
                $v += 1
            }
            elseif ($mode[$v] -eq 6){
                Write-Host "Warn" -ForegroundColor Yellow
                $v +=1
            }

       }
        if ($id -eq "9e6c4e1f-7d60-472f-ba1a-a39ef669e4b2") {
            Write-Host "# Block credential stealing from the Windows local security authority subsystem (lsass.exe)" -ForegroundColor Green
            if ($mode[$v] -eq 0){
                Write-Host "Not Configured or Disabled" -ForegroundColor DarkRed
                $v += 1
            }
            elseif ($mode[$v] -eq 1){
                Write-Host "Blocked" -ForegroundColor Red
                $v += 1
            }
            elseif ($mode[$v] -eq 2){
                Write-Host "Audit Mode" -ForegroundColor Magenta
                $v += 1
            }
            elseif ($mode[$v] -eq 6){
                Write-Host "Warn" -ForegroundColor Yellow
                $v +=1
            }

        }

        if ($id -eq "be9ba2d9-53ea-4cdc-84e5-9b1eeee46550") {
            Write-Host "# Block executable content from email client and webmail" -ForegroundColor Green
            if ($mode[$v] -eq 0){
                Write-Host "Not Configured or Disabled" -ForegroundColor DarkRed
                $v += 1
            }
            elseif ($mode[$v] -eq 1){
                Write-Host "Blocked" -ForegroundColor Red
                $v += 1
            }
            elseif ($mode[$v] -eq 2){
                Write-Host "Audit Mode" -ForegroundColor Magenta
                $v += 1
            }
            elseif ($mode[$v] -eq 6){
                Write-Host "Warn" -ForegroundColor Yellow
                $v +=1
            }

        }

        if ($id -eq "01443614-cd74-433a-b99e-2ecdc07bfc25") {
            Write-Host "# Block executable files from running unless they meet a prevalence, age, or trusted list criterion" -ForegroundColor Green
            if ($mode[$v] -eq 0){
                Write-Host "Not Configured or Disabled" -ForegroundColor DarkRed
                $v += 1
            }
            elseif ($mode[$v] -eq 1){
                Write-Host "Blocked" -ForegroundColor Red
                $v += 1
            }
            elseif ($mode[$v] -eq 2){
                Write-Host "Audit Mode" -ForegroundColor Magenta
                $v += 1
            }
            elseif ($mode[$v] -eq 6){
                Write-Host "Warn" -ForegroundColor Yellow
                $v +=1
            }

        }

        if ($id -eq "5beb7efe-fd9a-4556-801d-275e5ffc04cc") {
            Write-Host "# Block execution of potentially obfuscated scripts" -ForegroundColor Green
            if ($mode[$v] -eq 0){
                Write-Host "Not Configured or Disabled" -ForegroundColor DarkRed
                $v += 1
            }
            elseif ($mode[$v] -eq 1){
                Write-Host "Blocked" -ForegroundColor Red
                $v += 1
            }
            elseif ($mode[$v] -eq 2){
                Write-Host "Audit Mode" -ForegroundColor Magenta
                $v += 1
            }
            elseif ($mode[$v] -eq 6){
                Write-Host "Warn" -ForegroundColor Yellow
                $v +=1
            }

        }

        if ($id -eq "d3e037e1-3eb8-44c8-a917-57927947596d") {
            Write-Host "# Block JavaScript or VBScript from launching downloaded executable content" -ForegroundColor Green
            if ($mode[$v] -eq 0){
                Write-Host "Not Configured or Disabled" -ForegroundColor DarkRed
                $v += 1
            }
            elseif ($mode[$v] -eq 1){
                Write-Host "Blocked" -ForegroundColor Red
                $v += 1
            }
            elseif ($mode[$v] -eq 2){
                Write-Host "Audit Mode" -ForegroundColor Magenta
                $v += 1
            }
            elseif ($mode[$v] -eq 6){
                Write-Host "Warn" -ForegroundColor Yellow
                $v +=1
            }

        }

        if ($id -eq "3b576869-a4ec-4529-8536-b80a7769e899") {
            Write-Host "# Block Office applications from creating executable content" -ForegroundColor Green
            if ($mode[$v] -eq 0){
                Write-Host "Not Configured or Disabled" -ForegroundColor DarkRed
                $v += 1
            }
            elseif ($mode[$v] -eq 1){
                Write-Host "Blocked" -ForegroundColor Red
                $v += 1
            }
            elseif ($mode[$v] -eq 2){
                Write-Host "Audit Mode" -ForegroundColor Magenta
                $v += 1
            }
            elseif ($mode[$v] -eq 6){
                Write-Host "Warn" -ForegroundColor Yellow
                $v +=1
            }

        }

        if ($id -eq "75668c1f-73b5-4cf0-bb93-3ecf5cb7cc84") {
            Write-Host "# Block Office applications from injecting code into other processes" -ForegroundColor Green
            if ($mode[$v] -eq 0){
                Write-Host "Not Configured or Disabled" -ForegroundColor DarkRed
                $v += 1
            }
            elseif ($mode[$v] -eq 1){
                Write-Host "Blocked" -ForegroundColor Red
                $v += 1
            }
            elseif ($mode[$v] -eq 2){
                Write-Host "Audit Mode" -ForegroundColor Magenta
                $v += 1
            }
            elseif ($mode[$v] -eq 6){
                Write-Host "Warn" -ForegroundColor Yellow
                $v +=1
            }

        }

        if ($id -eq "26190899-1602-49e8-8b27-eb1d0a1ce869") {
            Write-Host "# Block Office communication application from creating child processes" -ForegroundColor Green
            if ($mode[$v] -eq 0){
                Write-Host "Not Configured or Disabled" -ForegroundColor DarkRed
                $v += 1
            }
            elseif ($mode[$v] -eq 1){
                Write-Host "Blocked" -ForegroundColor Red
                $v += 1
            }
            elseif ($mode[$v] -eq 2){
                Write-Host "Audit Mode" -ForegroundColor Magenta
                $v += 1
            }
            elseif ($mode[$v] -eq 6){
                Write-Host "Warn" -ForegroundColor Yellow
                $v +=1
            }


        }

        if ($id -eq "e6db77e5-3df2-4cf1-b95a-636979351e5b") {
            Write-Host "# Block persistence through WMI event subscription * File and folder exclusions not supported." -ForegroundColor Green
            if ($mode[$v] -eq 0){
                Write-Host "Not Configured or Disabled" -ForegroundColor DarkRed
                $v += 1
            }
            elseif ($mode[$v] -eq 1){
                Write-Host "Blocked" -ForegroundColor Red
                $v += 1
            }
            elseif ($mode[$v] -eq 2){
                Write-Host "Audit Mode" -ForegroundColor Magenta
                $v += 1
            }
            elseif ($mode[$v] -eq 6){
                Write-Host "Warn" -ForegroundColor Yellow
                $v +=1
            }

        }

        if ($id -eq "d1e49aac-8f56-4280-b9ba-993a6d77406c") {
            Write-Host "# Block process creations originating from PSExec and WMI commands" -ForegroundColor Green
            if ($mode[$v] -eq 0){
                Write-Host "Not Configured or Disabled" -ForegroundColor DarkRed
                $v += 1
            }
            elseif ($mode[$v] -eq 1){
                Write-Host "Blocked" -ForegroundColor Red
                $v += 1
            }
            elseif ($mode[$v] -eq 2){
                Write-Host "Audit Mode" -ForegroundColor Magenta
                $v += 1
            }
            elseif ($mode[$v] -eq 6){
                Write-Host "Warn" -ForegroundColor Yellow
                $v +=1
            }

        }

        if ($id -eq "b2b3f03d-6a65-4f7b-a9c7-1c7ef74a9ba4") {
            Write-Host "# Block untrusted and unsigned processes that run from USB" -ForegroundColor Green
            if ($mode[$v] -eq 0){
                Write-Host "Not Configured or Disabled" -ForegroundColor DarkRed
                $v += 1
            }
            elseif ($mode[$v] -eq 1){
                Write-Host "Blocked" -ForegroundColor Red
                $v += 1
            }
            elseif ($mode[$v] -eq 2){
                Write-Host "Audit Mode" -ForegroundColor Magenta
                $v += 1
            }
            elseif ($mode[$v] -eq 6){
                Write-Host "Warn" -ForegroundColor Yellow
                $v +=1
            }

        }

        if ($id -eq "92e97fa1-2edf-4476-bdd6-9dd0b4dddc7b") {
            Write-Host "# Block Win32 API calls from Office macros" -ForegroundColor Green
            if ($mode[$v] -eq 0){
                Write-Host "Not Configured or Disabled" -ForegroundColor DarkRed
                $v += 1
            }
            elseif ($mode[$v] -eq 1){
                Write-Host "Blocked" -ForegroundColor Red
                $v += 1
            }
            elseif ($mode[$v] -eq 2){
                Write-Host "Audit Mode" -ForegroundColor Magenta
                $v += 1
            }
            elseif ($mode[$v] -eq 6){
                Write-Host "Warn" -ForegroundColor Yellow
                $v +=1
            }

        }

        if ($id -eq "c1db55ab-c21a-4637-bb3f-a12568109d35") {
            Write-Host "# Use advanced protection against ransomware" -ForegroundColor Green
            if ($mode[$v] -eq 0){
                Write-Host "Not Configured or Disabled" -ForegroundColor DarkRed
                $v += 1
            }
            elseif ($mode[$v] -eq 1){
                Write-Host "Blocked" -ForegroundColor Red
                $v += 1
            }
            elseif ($mode[$v] -eq 2){
                Write-Host "Audit Mode" -ForegroundColor Magenta
                $v += 1
            }
            elseif ($mode[$v] -eq 6){
                Write-Host "Warn" -ForegroundColor Yellow
                $v +=1
            }

        }
    }

    
 }

ASRStatus

