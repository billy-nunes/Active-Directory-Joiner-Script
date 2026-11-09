#Requires -Version 5.1
#Requires -Modules ActiveDirectory
<#
.SYNOPSIS
    Interactive joiner script: creates a hybrid AD user from a joiner form, copying
    OU, groups, City and State from a model user.

.DESCRIPTION
    - Prompts for every joiner detail (no CSV, no input files)
    - Uses a separate privileged account for every AD read/write (-Credential),
      while the script itself runs as the logged-in person
    - Copies OU, group memberships, City and State from a model user
      (protected/admin groups are NOT copied and are flagged instead)
    - Builds a unique Firstname.Lastname username (max 20 characters)
    - Generates a three-word password that meets the domain minimum length
    - Shows a summary and only writes to AD after you confirm
    - Records who created the account in the Notes (info) attribute
    - Suggests a licence for manual assignment; it does NOT assign licences

    Safe by design:
    - Refuses to run if PowerShell transcription is enforced (the password is shown on screen)
    - Never writes the password to a file or log
    - Run with -WhatIf first: every prompt and lookup runs, nothing is written

.PARAMETER Domain
    Email / UPN suffix (e.g. contoso.com). Validated so a typo cannot create broken UPNs.

.PARAMETER Company
    Value written to the Company attribute.

.PARAMETER AdminAccountPrefix
    Prefix of the privileged account name. The credential prompt is pre-filled with
    "<prefix><your username>@<Domain>". Change it to match your naming convention.

.EXAMPLE
    .\New-ADJoiner.ps1 -WhatIf

.EXAMPLE
    .\New-ADJoiner.ps1 -Domain example.org -Company 'Example Ltd' -AdminAccountPrefix 'adm.'
#>

[CmdletBinding(SupportsShouldProcess)]
param(
    [ValidatePattern('^[a-z0-9.-]+\.[a-z]{2,}$')]
    [string]$Domain = 'contoso.com',

    [string]$Company = 'Contoso',

    [string]$AdminAccountPrefix = 'adm.'
)

$ErrorActionPreference = 'Stop'

#region ---------- Configuration (edit these for your organisation) ----------

# Location menu -> value written to the Office attribute
$OfficeByLocation = [ordered]@{
    'Head Office' = 'Contoso Head Office'
    'Store'       = 'Contoso Retail Staff'
    'Warehouse'   = 'Contoso Warehouse'
}

# Licence names shown in the summary (suggestion only; nothing is assigned)
$LicenceOptions = @('Microsoft 365 E3', 'Microsoft 365 F3', 'Entra ID P1')

# Non-office job titles -> licence. F3 is checked first.
$F3TitlePattern = 'assistant manager|store manager|general manager|branch manager'
$P1TitlePattern = 'supervisor|key ?holder|sales associate|sales consultant|consultant|associate'

# Employee number rule: 4-6 digits, or blank / 0000 if HR has not supplied it yet
$EmployeeNumberPattern = '^\d{4,6}$'

$PasswordSymbols = '!@#$%&*?'.ToCharArray()

# 3-5 letter words so three words + symbol + number land in 11-17 characters
$WordList = @(
    'acorn','amber','apple','arch','aspen','atlas','bagel','baker','bay','beach',
    'beam','bear','bell','berry','birch','bird','blaze','bloom','blue','boat',
    'bolt','brick','brook','bud','cabin','cake','camel','candy','cape','cargo',
    'cedar','chalk','chess','cider','cliff','cloud','clove','coast','cobra','comet',
    'coral','cove','crane','creek','crown','cub','daisy','dawn','delta','dew',
    'dove','drum','dune','eagle','earth','echo','elm','ember','fern','field',
    'fig','flame','flint','flute','foam','fox','frost','gale','gem','glow',
    'goat','grape','grove','gull','harp','hawk','hazel','heron','hill','honey',
    'horn','iris','ivy','jade','jazz','jelly','kayak','kite','koala','lake',
    'lamp','lark','leaf','lemon','lilac','lily','lime','lion','llama','lotus',
    'lunar','mango','maple','marsh','melon','mint','moon','moss','moth','music',
    'nest','noble','nova','oak','oasis','ocean','olive','onion','orbit','otter',
    'owl','palm','panda','pearl','petal','piano','pine','plum','polar','pond',
    'poppy','prism','quail','quiet','rain','raven','reef','ridge','river','robin',
    'rose','ruby','sage','sail','sand','scarf','seal','shell','silk','sky',
    'slate','snow','solar','spark','spice','star','stone','storm','sun','swan',
    'tango','tea','tiger','tide','toast','topaz','tulip','vale','vine','wave',
    'whale','wheat','wind','wolf','wren','yacht','yarn','zebra','zest'
)

#endregion

#region ---------- General helpers ----------

$script:Rng = New-Object System.Security.Cryptography.RNGCryptoServiceProvider

function Get-SecureRandom {
    # Cryptographically random integer from 0 to Max-1, with no modulo bias
    param([int]$Max)
    $bytes = New-Object byte[] 4
    [int64]$range = 4294967296
    [int64]$limit = $range - ($range % $Max)
    do {
        $script:Rng.GetBytes($bytes)
        [int64]$value = [BitConverter]::ToUInt32($bytes, 0)
    } while ($value -ge $limit)
    return [int]($value % $Max)
}

function ConvertTo-FilterValue {
    # Escapes single quotes for AD -Filter strings (e.g. O'Brien)
    param([string]$Value)
    return $Value -replace "'", "''"
}

function Get-NameFromDN {
    # 'CN=Sales Team,OU=Groups,DC=...' -> 'Sales Team'
    param([string]$DistinguishedName)
    return ($DistinguishedName -replace '^CN=((?:\\,|[^,])+),.*$', '$1') -replace '\\,', ','
}

function Read-NonEmpty {
    param([string]$Prompt)
    while ($true) {
        $value = (Read-Host $Prompt).Trim()
        if ($value) { return $value }
        Write-Host '  This field is required.' -ForegroundColor Yellow
    }
}

function Read-YesNo {
    param([string]$Prompt)
    while ($true) {
        $answer = (Read-Host "$Prompt (Y/N)").Trim().ToUpper()
        if ($answer -eq 'Y') { return $true }
        if ($answer -eq 'N') { return $false }
    }
}

function Select-Option {
    # Numbered menu; returns the chosen option text
    param([string]$Prompt, [string[]]$Options)
    Write-Host $Prompt
    for ($i = 0; $i -lt $Options.Count; $i++) {
        Write-Host ("  {0}) {1}" -f ($i + 1), $Options[$i])
    }
    while ($true) {
        $choice = (Read-Host 'Choose a number').Trim()
        $n = 0
        if ([int]::TryParse($choice, [ref]$n) -and $n -ge 1 -and $n -le $Options.Count) {
            return $Options[$n - 1]
        }
        Write-Host "  Enter a number from 1 to $($Options.Count)." -ForegroundColor Yellow
    }
}

#endregion

#region ---------- Joiner steps ----------

function Read-NamePart {
    param([string]$Label)
    while ($true) {
        $value = (Read-Host $Label).Trim()
        if ($value -match '^[A-Za-z]+$') { return $value }
        Write-Host "  Invalid $($Label.ToLower()): letters only (no hyphens, apostrophes, spaces, numbers or accents)." -ForegroundColor Red
    }
}

function Format-UsernamePart {
    # 'mcDONALD' -> 'Mcdonald'
    param([string]$Value)
    return $Value.Substring(0, 1).ToUpper() + $Value.Substring(1).ToLower()
}

function Test-IdentityInUse {
    # True if the username, UPN or email is taken by any AD object (case-insensitive)
    param([string]$Sam, [string]$Address)
    $s = ConvertTo-FilterValue $Sam
    $a = ConvertTo-FilterValue $Address
    $filter = "sAMAccountName -eq '$s' -or userPrincipalName -eq '$a' -or mail -eq '$a' -or proxyAddresses -eq 'smtp:$a'"
    return [bool](Get-ADObject -Filter $filter @script:AD)
}

function Get-AvailableUsername {
    # Firstname.Lastname, then Firstname.Lastname1, 2... Flags anything over 20 characters.
    param([string]$First, [string]$Last)
    $base = '{0}.{1}' -f (Format-UsernamePart $First), (Format-UsernamePart $Last)
    $suffix = 0
    while ($true) {
        $sam = if ($suffix -eq 0) { $base } else { "$base$suffix" }
        if ($sam.Length -gt 20) {
            return [pscustomobject]@{ Sam = $sam; TooLong = $true; Suffix = $suffix }
        }
        if (-not (Test-IdentityInUse -Sam $sam -Address "$sam@$Domain")) {
            return [pscustomobject]@{ Sam = $sam; TooLong = $false; Suffix = $suffix }
        }
        $suffix++
    }
}

function Read-EmployeeNumber {
    # Returns the employee number, or $null if HR has not supplied it yet
    while ($true) {
        $n = (Read-Host 'Employee number (leave blank if not yet supplied by HR)').Trim()
        if (-not $n -or $n -eq '0000') { return $null }
        if ($n -notmatch $EmployeeNumberPattern) {
            Write-Host '  Employee number must be 4-6 digits.' -ForegroundColor Red
            continue
        }
        $existing = @(Get-ADUser -Filter "employeeID -eq '$n'" @script:AD)
        if ($existing.Count -gt 0) {
            Write-Host "  Employee number $n is already on $($existing[0].SamAccountName). Check the form." -ForegroundColor Red
            continue
        }
        return $n
    }
}

function Read-Manager {
    # Exact match -> use it. Several or partial matches -> pick from a list. S -> skip.
    while ($true) {
        $name = (Read-Host "Line manager's name (or S to skip)").Trim()
        if (-not $name) { continue }
        if ($name -eq 'S') { return $null }

        $n = ConvertTo-FilterValue $name
        $props = @('DisplayName', 'Title', 'Department', 'UserPrincipalName')
        $found = @(Get-ADUser -Filter "(displayName -eq '$n' -or name -eq '$n') -and enabled -eq 'True'" -Properties $props @script:AD)
        $exact = $true

        if ($found.Count -eq 0) {
            $found = @(Get-ADUser -Filter "displayName -like '*$n*' -and enabled -eq 'True'" -Properties $props @script:AD)
            $exact = $false
        }

        if ($found.Count -eq 0) {
            Write-Host "  No enabled user found matching '$name'. Try again or press S to skip." -ForegroundColor Red
            continue
        }

        if ($found.Count -eq 1 -and $exact) { return $found[0] }

        Write-Host "  Matches for '$name':" -ForegroundColor Yellow
        for ($i = 0; $i -lt $found.Count; $i++) {
            $u = $found[$i]
            Write-Host ("  {0}) {1} | {2} | {3} | {4}" -f ($i + 1), $u.DisplayName, $u.Title, $u.Department, $u.UserPrincipalName)
        }
        $choice = (Read-Host 'Choose a number, R to search again, or S to skip').Trim().ToUpper()
        if ($choice -eq 'S') { return $null }
        $idx = 0
        if ([int]::TryParse($choice, [ref]$idx) -and $idx -ge 1 -and $idx -le $found.Count) {
            return $found[$idx - 1]
        }
    }
}

function Read-ModelUser {
    while ($true) {
        $email = Read-NonEmpty 'Model user email (or just first.last)'
        if ($email -notmatch '@') { $email = "$email@$Domain" }
        $e = ConvertTo-FilterValue $email
        $found = @(Get-ADUser -Filter "mail -eq '$e' -or userPrincipalName -eq '$e'" `
                    -Properties MemberOf, City, State, Office, DisplayName, Enabled @script:AD)
        if ($found.Count -eq 0) {
            Write-Host "  No user found with email '$email'." -ForegroundColor Red
            continue
        }
        if ($found.Count -gt 1) {
            Write-Host "  More than one user matches '$email'. Check AD." -ForegroundColor Red
            continue
        }
        if (-not $found[0].Enabled) {
            # A disabled model is often a leaver whose groups have been stripped
            if (-not (Read-YesNo "  $($found[0].DisplayName) is disabled (possible leaver). Use anyway?")) { continue }
        }
        return $found[0]
    }
}

function Get-SuggestedLicence {
    # Location is checked before title, so "Merchandising Assistant" at Head Office is not matched as a store role
    param([string]$Location, [string]$JobTitle)
    if ($Location -in @('Head Office', 'Warehouse')) { return 'Microsoft 365 E3' }
    if ($JobTitle -match $F3TitlePattern) { return 'Microsoft 365 F3' }
    if ($JobTitle -match $P1TitlePattern) { return 'Entra ID P1' }
    return $null
}

function Get-AvailableCN {
    # The AD object name (CN) must be unique within the OU
    param([string]$DisplayName, [string]$OU)
    $cn = $DisplayName
    $i = 1
    while (Get-ADObject -SearchBase $OU -SearchScope OneLevel -Filter "name -eq '$(ConvertTo-FilterValue $cn)'" @script:AD) {
        $cn = "$DisplayName $i"
        $i++
    }
    return $cn
}

function New-JoinerPassword {
    # Three words (first capitalised), then a symbol and a number. Length is
    # $script:PwMin to $script:PwMax, set from the domain's minimum password length.
    # Example shape: Applegraintrain@1
    param([string]$First, [string]$Last)
    while ($true) {
        $words = @(1..3 | ForEach-Object { $WordList[(Get-SecureRandom $WordList.Count)] })
        $length = ($words | Measure-Object -Property Length -Sum).Sum + 2
        if ($length -lt $script:PwMin -or $length -gt $script:PwMax) { continue }

        $words[0] = $words[0].Substring(0, 1).ToUpper() + $words[0].Substring(1)
        $symbol   = [string]$PasswordSymbols[(Get-SecureRandom $PasswordSymbols.Count)]
        $number   = [string](Get-SecureRandom 10)
        $password = ($words -join '') + $symbol + $number

        # AD complexity rejects passwords containing parts of the user's name (3+ characters)
        $clash = $false
        foreach ($namePart in @($First, $Last)) {
            if ($namePart.Length -ge 3 -and $password.ToLower().Contains($namePart.ToLower())) { $clash = $true }
        }
        if ($clash) { continue }

        return $password
    }
}

#endregion

#region ---------- One joiner ----------

function Invoke-Joiner {
    $flags = New-Object System.Collections.Generic.List[string]

    Write-Host ''
    Write-Host '==================== New joiner ====================' -ForegroundColor Cyan

    # 1. Ticket
    $ticket = (Read-NonEmpty 'Ticket number').TrimStart('#')

    # 2-3. Names and username (re-prompts if too long)
    while ($true) {
        $first = Read-NamePart 'First name'
        $last  = Read-NamePart 'Last name'
        $script:CurrentJoiner = "$first $last"
        $user = Get-AvailableUsername -First $first -Last $last
        if ($user.TooLong) {
            Write-Host "  Username '$($user.Sam)' is $($user.Sam.Length) characters (max 20). Use a shortened name, then re-enter it." -ForegroundColor Red
            continue
        }
        if ($user.Suffix -gt 0) {
            Write-Host "  $first $last already has an account; using $($user.Sam)." -ForegroundColor Yellow
        }
        break
    }
    $sam         = $user.Sam
    $upn         = "$sam@$Domain"
    $displayName = "$first $last"

    # 4-6. Role details
    $title      = Read-NonEmpty 'Job title'
    $department = Read-NonEmpty 'Department (from the form)'
    $location   = Select-Option -Prompt 'Location:' -Options @($OfficeByLocation.Keys)
    $office     = $OfficeByLocation[$location]

    # 7. Line manager
    $manager = Read-Manager
    if (-not $manager) { $flags.Add('Manager skipped') }

    # 8. Model user
    $model = Read-ModelUser
    $ou    = $model.DistinguishedName -replace '^CN=(?:\\,|[^,])+,', ''
    if ($model.Office -and $model.Office -ne $office) {
        Write-Host "  Warning: model user's Office is '$($model.Office)' but you chose $location." -ForegroundColor Yellow
        $flags.Add('Model user location mismatch')
    }

    # 9. Employee number
    $employeeNumber = Read-EmployeeNumber
    if (-not $employeeNumber) { $flags.Add('Employee number pending') }

    # 10. Description
    $defaultDescription = "$title - $department"
    $description = (Read-Host "Description [Enter to accept: $defaultDescription]").Trim()
    if (-not $description) { $description = $defaultDescription }

    # Licence suggestion
    $licence = Get-SuggestedLicence -Location $location -JobTitle $title
    if (-not $licence) {
        $licence = Select-Option -Prompt "No licence match for '$title'. Which licence?" -Options $LicenceOptions
    }

    # Audit note
    $note = "Created by $($env:USERNAME.ToLower()) via joiner script, $(Get-Date -Format 'dd/MM/yyyy'), Ticket #$ticket"
    if (-not $employeeNumber) { $note += ' - EMPLOYEE NUMBER PENDING' }

    $cn = Get-AvailableCN -DisplayName $displayName -OU $ou

    # Groups: never copy protected (AdminSDHolder) groups such as Domain Admins
    $groups = @($model.MemberOf)
    $protected = @($groups | Where-Object {
        (Get-ADGroup -Identity $_ -Properties adminCount @script:AD).adminCount -eq 1
    })
    if ($protected.Count -gt 0) {
        $groups = @($groups | Where-Object { $_ -notin $protected })
        $flags.Add("Protected groups NOT copied: $(($protected | ForEach-Object { Get-NameFromDN $_ }) -join ', ')")
    }

    # ---------- Summary ----------
    $summary = [ordered]@{
        'Display name'      = $displayName
        'Username'          = $sam
        'Email / UPN'       = $upn
        'OU'                = $ou
        'Job title'         = $title
        'Department'        = $department
        'Description'       = $description
        'Office'            = $office
        'Company'           = $Company
        'Employee number'   = $(if ($employeeNumber) { $employeeNumber } else { 'PENDING' })
        'Line manager'      = $(if ($manager) { $manager.DisplayName } else { 'SKIPPED' })
        'Model user'        = $model.DisplayName
        'City'              = $model.City
        'State'             = $model.State
        'Groups to copy'    = "$($groups.Count)"
        'Suggested licence' = "$licence (assign manually)"
        'Notes'             = $note
    }
    Write-Host ''
    Write-Host '---------------- Summary ----------------' -ForegroundColor Cyan
    foreach ($key in $summary.Keys) {
        Write-Host ("  {0,-18} {1}" -f $key, $summary[$key])
    }
    foreach ($g in $groups) { Write-Host "      - $(Get-NameFromDN $g)" }
    foreach ($f in $flags)  { Write-Host "  FLAG: $f" -ForegroundColor Yellow }
    Write-Host '  Note: cloud-only groups (Teams / M365) are not in AD and are not copied.' -ForegroundColor DarkGray

    $result = [pscustomobject]@{
        Joiner   = $displayName
        Username = $sam
        Result   = ''
        Licence  = $licence
        Flags    = ''
    }

    if (-not (Read-YesNo 'Create this account?')) {
        $result.Result = 'Discarded'
        return $result
    }

    # ---------- WhatIf: stop before writing ----------
    if ($WhatIfPreference) {
        Write-Host "  WHAT IF: would create $sam in $ou and add $($groups.Count) groups." -ForegroundColor Magenta
        $samplePassword = New-JoinerPassword -First $first -Last $last
        Write-Host "  WHAT IF: sample password (not set on any account): $samplePassword" -ForegroundColor Magenta
        $samplePassword = $null
        $result.Result = 'WhatIf'
        $result.Flags  = $flags -join '; '
        return $result
    }

    # ---------- Create ----------
    $password = New-JoinerPassword -First $first -Last $last

    $newUser = @{
        Name                  = $cn
        DisplayName           = $displayName
        GivenName             = $first
        Surname               = $last
        SamAccountName        = $sam
        UserPrincipalName     = $upn
        EmailAddress          = $upn
        Path                  = $ou
        AccountPassword       = (ConvertTo-SecureString $password -AsPlainText -Force)
        Enabled               = $true
        ChangePasswordAtLogon = $false
        Title                 = $title
        Department            = $department
        Description           = $description
        Office                = $office
        Company               = $Company
        OtherAttributes       = @{ info = $note }
    }
    if ($employeeNumber) { $newUser.EmployeeID = $employeeNumber }
    if ($manager)        { $newUser.Manager    = $manager.DistinguishedName }
    if ($model.City)     { $newUser.City       = $model.City }
    if ($model.State)    { $newUser.State      = $model.State }

    try {
        New-ADUser @newUser @script:AD
    } catch {
        $leftover = Get-ADUser -Filter "sAMAccountName -eq '$sam'" @script:AD
        if ($leftover) {
            Write-Host "  $sam was partly created before the error. Check it in ADUC and delete it before retrying." -ForegroundColor Red
        }
        throw
    }
    Write-Host "  Created $sam." -ForegroundColor Green

    # ---------- Copy groups ----------
    $failedGroups = New-Object System.Collections.Generic.List[string]
    foreach ($g in $groups) {
        try {
            Add-ADGroupMember -Identity $g -Members $sam @script:AD
        } catch {
            $failedGroups.Add((Get-NameFromDN $g))
            Write-Host "  Could not add to group $(Get-NameFromDN $g): $($_.Exception.Message)" -ForegroundColor Yellow
        }
    }
    Write-Host "  Added to $($groups.Count - $failedGroups.Count) of $($groups.Count) groups." -ForegroundColor Green
    if ($failedGroups.Count -gt 0) { $flags.Add("Failed groups: $($failedGroups -join ', ')") }

    # ---------- Show password once ----------
    Write-Host ''
    Write-Host "  Password for $sam : " -NoNewline
    Write-Host $password -ForegroundColor Green
    Write-Host '  Copy it NOW and store it securely until the start date. It is not saved anywhere.' -ForegroundColor Yellow
    [void](Read-Host '  Press Enter to clear the screen')
    $password = $null
    Clear-Host

    $result.Result = 'Created'
    $result.Flags  = $flags -join '; '
    return $result
}

#endregion

#region ---------- Main ----------

Write-Host 'Joiner Script' -ForegroundColor Cyan
if ($WhatIfPreference) { Write-Host 'WHAT IF MODE: nothing will be written to AD.' -ForegroundColor Magenta }

# The password is shown on screen, so refuse to run if transcription would capture it
$tx = Get-ItemProperty 'HKLM:\SOFTWARE\Policies\Microsoft\Windows\PowerShell\Transcription' -ErrorAction SilentlyContinue
if ($tx -and $tx.EnableTranscripting -eq 1) {
    Write-Host 'PowerShell transcription is enforced on this PC; the password would be saved to disk. Exiting.' -ForegroundColor Red
    return
}

# Privileged credential (held in memory for this run only, never saved or displayed)
$cred = Get-Credential -UserName "$AdminAccountPrefix$env:USERNAME@$Domain" -Message 'Enter your privileged account and its password'
if (-not $cred) { Write-Host 'No credential entered. Exiting.' -ForegroundColor Red; return }

# One writable domain controller for the whole run, so new accounts are visible immediately.
# No -DomainName: the PC's own domain is used (the email domain is often different from the AD domain).
try {
    $dc = Get-ADDomainController -Discover -Writable
    $server = [string]$dc.HostName
    $script:AD = @{ Server = $server; Credential = $cred }
    [void](Get-ADDomain @script:AD)

    # Password length follows the domain policy (fine-grained policies are not visible here)
    $minLen = (Get-ADDefaultDomainPasswordPolicy @script:AD).MinPasswordLength
} catch {
    Write-Host "Could not connect to AD with that credential: $($_.Exception.Message)" -ForegroundColor Red
    return
}

# 3 words of 3-5 letters + symbol + number can reach 17 characters at most
$script:PwMin = [Math]::Max(12, [int]$minLen)
$script:PwMax = $script:PwMin + 2
if ($script:PwMin -gt 17) {
    Write-Host "Domain requires $minLen+ character passwords; this generator makes up to 17. Add a fourth word to the generator. Exiting." -ForegroundColor Red
    return
}

Write-Host "Connected to $server as $($cred.UserName). Run by $env:USERNAME. Passwords: $script:PwMin-$script:PwMax characters." -ForegroundColor Green

$results = New-Object System.Collections.Generic.List[object]

do {
    $script:CurrentJoiner = ''
    try {
        $results.Add((Invoke-Joiner))
    } catch {
        Write-Host "  FAILED: $($_.Exception.Message)" -ForegroundColor Red
        $results.Add([pscustomobject]@{
            Joiner   = $script:CurrentJoiner
            Username = ''
            Result   = 'Failed'
            Licence  = ''
            Flags    = $_.Exception.Message
        })
    }
} while (Read-YesNo 'Add another joiner?')

Write-Host ''
Write-Host '================ Run summary ================' -ForegroundColor Cyan
$results | Format-Table Joiner, Username, Result, Licence, Flags -AutoSize -Wrap

#endregion
