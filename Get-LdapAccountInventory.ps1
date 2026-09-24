<#
.SYNOPSIS
    Exporte l'inventaire des comptes utilisateur d'un annuaire Active Directory en CSV (lecture
    seule) : état, dates de création / dernière connexion / mot de passe, OU, nombre de groupes.

.DESCRIPTION
    Complète Get-LdapAppRoleAudit.ps1, qui liste les rôles et leurs membres mais ne dit rien sur
    les comptes eux-mêmes. Cet inventaire alimente la détection des comptes dormants, orphelins et
    leavers encore actifs (IAM-Access-Recertification, Find-DormantAccounts.ps1).

    Lecture LDAP seule, sans dépendance au module ActiveDirectory. Pagination activée : fonctionne
    au-delà de la limite de 1000 objets par requête.

    Attention à la précision de la dernière connexion : lastLogonTimestamp est répliqué avec un
    décalage pouvant atteindre ~14 jours et ne vaut que pour des seuils de l'ordre de plusieurs
    dizaines de jours (30, 60, 90). Il est vide pour un compte qui ne s'est jamais connecté.

.PARAMETER LdapServer
    Contrôleur de domaine. DC1.society.local par défaut.

.PARAMETER Port
    389 par défaut (lab sans LDAPS). Utiliser 636 avec -UseTls contre un annuaire réel.

.PARAMETER UseTls
    Utilise LDAPS. À activer contre tout annuaire de production.

.PARAMETER BaseDN
    Racine de la recherche. DC=society,DC=local par défaut.

.PARAMETER Credential
    Identifiants du bind (SOCIETY\Administrateur). Demandés si omis.

.PARAMETER OutputCsv
    CSV de sortie. Accounts_Inventory.csv dans le dossier du script par défaut.

.EXAMPLE
    .\Get-LdapAccountInventory.ps1
#>

[CmdletBinding()]
param(
    [string]$LdapServer = "DC1.society.local",
    [int]$Port = 389,
    [switch]$UseTls,
    [string]$BaseDN = "DC=society,DC=local",
    [System.Management.Automation.PSCredential]$Credential,
    [string]$OutputCsv = (Join-Path $PSScriptRoot "Accounts_Inventory.csv")
)

Add-Type -AssemblyName System.DirectoryServices.Protocols

if (-not $Credential) {
    $Credential = Get-Credential -Message "Identifiants pour le bind sur $LdapServer (ex: SOCIETY\Administrateur)"
}
if (-not $Credential) {
    Write-Host "ERREUR : aucun identifiant fourni." -ForegroundColor Red
    exit 1
}

$bindUser = $Credential.UserName
if ($bindUser -match '^([^\\]+)\\(.+)$') {
    $netCred = New-Object System.Net.NetworkCredential($matches[2], $Credential.GetNetworkCredential().Password, $matches[1])
    $authType = [System.DirectoryServices.Protocols.AuthType]::Negotiate
}
else {
    $netCred = New-Object System.Net.NetworkCredential($bindUser, $Credential.GetNetworkCredential().Password)
    $authType = [System.DirectoryServices.Protocols.AuthType]::Basic
}

$connection = New-Object System.DirectoryServices.Protocols.LdapConnection(
    (New-Object System.DirectoryServices.Protocols.LdapDirectoryIdentifier($LdapServer, $Port)))
$connection.Credential = $netCred
$connection.AuthType = $authType
$connection.SessionOptions.ProtocolVersion = 3
if ($UseTls) { $connection.SessionOptions.SecureSocketLayer = $true }

try { $connection.Bind($netCred) }
catch {
    Write-Host "ERREUR LDAP : $($_.Exception.Message)" -ForegroundColor Red
    Write-Host "Vérifiez le mot de passe et que le compte n'est pas verrouillé." -ForegroundColor Yellow
    exit 1
}
Write-Host "Connecté à $LdapServer`:$Port (TLS: $([bool]$UseTls))" -ForegroundColor Green

[string[]]$attributes = @("sAMAccountName", "cn", "distinguishedName", "userAccountControl", "whenCreated",
    "lastLogonTimestamp", "pwdLastSet", "description", "department", "memberOf")

$request = New-Object System.DirectoryServices.Protocols.SearchRequest(
    $BaseDN,
    "(&(objectCategory=person)(objectClass=user))",
    [System.DirectoryServices.Protocols.SearchScope]::Subtree,
    $attributes)
$pageControl = New-Object System.DirectoryServices.Protocols.PageResultRequestControl(500)
[void]$request.Controls.Add($pageControl)

function Get-Attr {
    param($Entry, [string]$Name)
    if ($Entry.Attributes.Contains($Name) -and $Entry.Attributes[$Name].Count -gt 0) {
        $v = $Entry.Attributes[$Name][0]
        if ($v -is [byte[]]) { return [System.Text.Encoding]::UTF8.GetString($v) }
        return [string]$v
    }
    return ""
}

function ConvertFrom-FileTimeText {
    param([string]$Text)
    if (-not $Text) { return "" }
    $n = 0L
    if (-not [int64]::TryParse($Text, [ref]$n)) { return "" }
    if ($n -le 0 -or $n -ge 9223372036854775807) { return "" }
    return [DateTime]::FromFileTimeUtc($n).ToString("yyyy-MM-dd")
}

$rows = [System.Collections.Generic.List[object]]::new()
do {
    $response = $connection.SendRequest($request)
    foreach ($entry in $response.Entries) {
        $dn = $entry.DistinguishedName
        $uac = 0
        [void][int]::TryParse((Get-Attr $entry "userAccountControl"), [ref]$uac)

        $created = ""
        $whenCreated = Get-Attr $entry "whenCreated"
        if ($whenCreated.Length -ge 8) { $created = $whenCreated.Substring(0, 4) + "-" + $whenCreated.Substring(4, 2) + "-" + $whenCreated.Substring(6, 2) }

        $groupCount = if ($entry.Attributes.Contains("memberOf")) { $entry.Attributes["memberOf"].Count } else { 0 }

        [void]$rows.Add([PSCustomObject]@{
            SamAccountName = Get-Attr $entry "sAMAccountName"
            Name           = Get-Attr $entry "cn"
            OU             = ($dn -split ',', 2)[1]
            Enabled        = if (($uac -band 2) -eq 0) { "True" } else { "False" }
            WhenCreated    = $created
            LastLogon      = ConvertFrom-FileTimeText (Get-Attr $entry "lastLogonTimestamp")
            PasswordLastSet = ConvertFrom-FileTimeText (Get-Attr $entry "pwdLastSet")
            Description    = Get-Attr $entry "description"
            Department     = Get-Attr $entry "department"
            GroupCount     = $groupCount
        })
    }
    $pageResponse = $response.Controls | Where-Object { $_ -is [System.DirectoryServices.Protocols.PageResultResponseControl] }
    $pageControl.Cookie = if ($pageResponse) { $pageResponse.Cookie } else { $null }
} while ($pageControl.Cookie -and $pageControl.Cookie.Length -gt 0)

$rows | Sort-Object OU, SamAccountName | Export-Csv $OutputCsv -NoTypeInformation -Encoding UTF8
Write-Host "`n=== Export terminé : $OutputCsv ($($rows.Count) comptes) ===" -ForegroundColor Green
