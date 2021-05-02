<#
# BreachCheck API (BCA) - Created by -Kai {https://kai.wtf}
# Created 2nd May, 2021
#
# GitHub: https://github.com/KaiBurton
#>

<# CHANGE ME #>
$script:Password = ""
<# MD5, SHA-1, SHA-256, SHA-512 & PLAIN-TEXT #>
$script:HashType = "SHA-1"
<# $True = HTTPS, $False = HTTP #>
$script:UsingHttps = $True

<# DO NOT CHANGE #>
$script:ApiUrl = "api.rsps.tools/jetkai/breachcheck"
$script:Token = "39439e74fa27c09a4"

<# Data that is returned from the api #>
$script:RestResponse = ""

<# This function is an example to view if the password "password123" is breached, using SHA-1 & HTTPS #>
Function Invoke-BcaExample {
    Write-Host -ForegroundColor Yellow 'Example: Executing - Invoke-BcaRestMethod -Password "password123" -HashType "SHA-1" -UsingHttps $True'
    $script:Password = "password123"
    $script:HashType = "SHA-1"
    $script:UsingHttps = $True
    Invoke-BcaRestMethod -Password $script:Password -HashType $script:HashType -UsingHttps $script:UsingHttps
}

Function New-BcaRequest {
    [CmdletBinding()]
    param(
        [Parameter(Mandatory=$True)][string]$Password,
        [string]$HashType,
        [string]$UsingHttps
    )

    $script:Password = $Password
    If($null -ne $HashType) {
        $script:HashType = $HashType
    }
    If($null -ne $UsingHttps) {
        $script:UsingHttps = $UsingHttps
    }
    
    Invoke-BcaRestMethod -Password $Password -HashType $HashType -UsingHttps $UsingHttps
}


<#   Sends HTTP Request to the API, setting the returnedJson string with returned JSON data
#
#   URL Request Example:
#   https://api.rsps.tools/jetkai/breachcheck?token=39439e74fa27c09a4&hash=ed8779a2222dc578f2cffbf308411b41381a94ef25801f9dfbe04746ea0944cd
# 
#   Returned JSON Data Example:
#   {
#   	"token": "39439e74fa27c09a4",
#   	"hash": "ed8779a2222dc578f2cffbf308411b41381a94ef25801f9dfbe04746ea0944cd",
#   	"hashPos": 2,
#   	"severity": "Top 100 Common Passwords",
#   	"databaseBreach": "Stoned 2021 ~800K Unique Passwords (15+ RSPS Databases)",
#   	"hashType": "SHA-256",
#   	"breached": true
#   }
#>
Function Invoke-BcaRestMethod {
   
    $CheckField = Get-BcaCheckField
    If($CheckField.Length -gt 0) {
        Write-Host -ForegroundColor Red $CheckField
    }

    $HashOrPassword = Search-BcaHashByType -Type "HASH_TYPE"
    $HashedPassword = Search-BcaHashByType -Type "HASH_PASSWORD"
    $Protocol = Get-BcaRestProtocol
    $ParsedURL = $Protocol + $script:ApiUrl + "?token=" + $script:Token + "&" + $HashOrPassword + "=" + $HashedPassword
 
    $script:RestResponse = Invoke-RestMethod -Uri $ParsedURL

    $Breached = Get-BcaHashBreached
    If($Breached) {
        Write-Host -ForegroundColor Red "You have been breached"
    } else {
        Write-Host -ForegroundColor Green "You have not been breached" 
    }

    Get-BcaRestResponse
}

<#  Temp Get-BcaCheckField, too sleepy to do much more here
#
#   Checks Fields
#   @return The string output if the password /or token field is null/empty
#
#>
Function Get-BcaCheckField {
    If(($null -eq $script:Password) -or ($script:Password.Length -eq 0)) {
        return "Password field can't be empty"
    } ElseIf(($null -eq $script:Token) -or ($script:Token.Length -eq 0)) {
        return "Password field can't be empty"
    } ElseIf(($null -eq $script:UsingHttps) -or ($script:UsingHttps.Length -eq 0)) {
        return "UsingHttps boolean can't be empty"
    } ElseIf(($null -eq $script:HashType) -or ($script:HashType.Length -eq 0)) {
        return "HashType field can't be empty"
    }
    return ""
}

Function Search-BcaHashByType {
    [CmdletBinding()] param([Parameter(Mandatory=$True)][string]$Type)
    $Hash = ""
    $HashTypes = @('MD5', 'SHA-1', 'SHA-256', 'SHA-512')
    ForEach ($HashType in $HashTypes) {
        If($HashType.ToUpper() -eq $script:HashType) {
            switch($Type) {
                "HASH_PASSWORD" {
                    $HashType = $HashType.Replace("-", "")
                    [System.Security.Cryptography.HashAlgorithm]::Create($HashType).ComputeHash([System.Text.Encoding]::UTF8.GetBytes($script:Password)) | ForEach-Object -Process {
                        $Hash += ($_.ToString('x2'))
                    }
                    If($Hash -eq "") {
                        return $script:Password
                    } else {
                        return $Hash
                    }
                }

                "HASH_TYPE" {
                    If($HashType -eq $script:HashType) {
                        return "hash"
                    }
                    return "password"
                }
            }
        }
    }
}

Function Set-BcaRestResponse {
    [CmdletBinding()] param([Parameter(Mandatory=$True)][string]$RestResponse)
    $script:RestResponse = $RestResponse
}

Function Set-BcaToken {
    [CmdletBinding()] param([Parameter(Mandatory=$True)][string]$Token)
    $script:Token = $Token
}

Function Set-BcaApiUrl {
    [CmdletBinding()] param([Parameter(Mandatory=$True)][string]$ApiUrl)
    $script:ApiUrl = $ApiUrl
}

Function Set-BcaHashType {
    [CmdletBinding()] param([Parameter(Mandatory=$True)][string]$HashType)
    $script:HashType = $HashType
}

Function Get-BcaRestProtocol {
    If($script:UsingHttps -eq $True) {
        return "https://"
    }
    return "http://"
}

Function Get-BcaHashBreached {
    If(($null -ne $script:RestResponse) -and ($script:RestResponse.breached)) {
        return $True
    }
    return $False
}

Function Get-BcaRestResponse {
    return $script:RestResponse
}

Function Get-BcaToken {
    return $script:Token
}

Function Get-BcaApiUrl {
    return $script:ApiUrl
}

Function Get-BcaHashType {
    return $script:HashType
}

Function Get-BcaPassword {
    return $script:Password
}

Function Get-BcaUsingHttps {
    return $script:UsingHttps
}