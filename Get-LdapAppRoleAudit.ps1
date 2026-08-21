<#
.SYNOPSIS
    Interroge un annuaire LDAP pour produire un export CSV Application / Rôle / Description,
    utile pour des audits d'accès applicatifs (IAM/GRC).

.DESCRIPTION
    Recherche, sous une base DN donnée, les groupes correspondant à un ensemble d'identifiants
    d'application fournis par l'opérateur, puis pour chacun, recherche ses sous-groupes
    (assimilés ici à des rôles) et exporte le tout en CSV.

    Schéma utilisé ici : objectClass standard `groupOfUniqueNames` (RFC 2256), pas un schéma
    propriétaire — à adapter aux object classes/attributs réels de votre annuaire (ex:
    remplacer -AppObjectClass par la classe applicative de votre organisation).

.PARAMETER LdapServer
    Nom d'hôte du serveur LDAP.

.PARAMETER Port
    Port LDAP. 636 (LDAPS) par défaut — voir la note sécurité ci-dessous.

.PARAMETER UseTls
    Utilise LDAPS (chiffré). Désactiver uniquement contre un serveur de test qui ne le supporte
    pas (voir note sécurité) — ne jamais désactiver contre un annuaire de production.

.PARAMETER BaseDN
    Base DN sous laquelle chercher les applications.

.PARAMETER BindDN
    DN utilisé pour l'authentification.

.PARAMETER AppIds
    Un ou plusieurs identifiants d'application à rechercher (ex: noms de groupes).

.PARAMETER AppObjectClass
    objectClass identifiant une "application" dans votre annuaire. `groupOfUniqueNames` par
    défaut (générique) — à remplacer par la classe propre à votre organisation le cas échéant.

.EXAMPLE
    # Démo contre le serveur de test public ldap.forumsys.com (lecture seule, sans authentification
    # applicative réelle — voir "NOTE SÉCURITÉ" plus bas pour -UseTls:$false)
    .\Get-LdapAppRoleAudit.ps1 `
        -LdapServer "ldap.forumsys.com" -Port 389 -UseTls:$false `
        -BaseDN "dc=example,dc=com" `
        -BindDN "cn=read-only-admin,dc=example,dc=com" `
        -AppIds "scientists","mathematicians","chemists"

.NOTES
    NOTE SÉCURITÉ — pourquoi LDAPS par défaut :
    Un bind LDAP simple (Basic) sur port 389 sans TLS transmet l'identifiant ET le mot de passe
    en clair sur le réseau — quiconque peut sniffer le trafic (switch compromis, ARP spoofing,
    proxy intermédiaire) récupère des identifiants valides. LDAPS (636) ou StartTLS chiffrent la
    session avant l'envoi des identifiants. Ce script utilise LDAPS par défaut ; -UseTls:$false
    n'existe que pour permettre de tester contre le serveur public ldap.forumsys.com, qui est un
    service de démo ancien ne supportant plus aucune variante de TLS actuelle (vérifié : ni LDAPS
    ni StartTLS n'aboutissent contre ce serveur au moment de l'écriture) — ce n'est PAS le
    comportement à reproduire contre un annuaire réel.
#>

[CmdletBinding()]
param(
    [Parameter(Mandatory)]
    [string]$LdapServer,

    [int]$Port = 636,

    [bool]$UseTls = $true,

    [Parameter(Mandatory)]
    [string]$BaseDN,

    [Parameter(Mandatory)]
    [string]$BindDN,

    [Parameter(Mandatory)]
    [securestring]$Password = $(Read-Host -Prompt "Mot de passe LDAP" -AsSecureString),

    [Parameter(Mandatory)]
    [string[]]$AppIds,

    [string]$AppObjectClass = "groupOfUniqueNames",
    [string]$RoleObjectClass = "groupOfUniqueNames",

    [string]$OutputCsv = "LDAP_Applications_Roles_Audit.csv"
)

Add-Type -AssemblyName System.DirectoryServices.Protocols

$bstr = [System.Runtime.InteropServices.Marshal]::SecureStringToBSTR($Password)
# PtrToStringBSTR (pas PtrToStringAuto) : ce dernier lit mal le préfixe de longueur du BSTR
# sur .NET/Linux et tronque silencieusement le mot de passe (vérifié : "password" -> "p").
$plainPassword = [System.Runtime.InteropServices.Marshal]::PtrToStringBSTR($bstr)
[System.Runtime.InteropServices.Marshal]::ZeroFreeBSTR($bstr)

$credential = New-Object System.Net.NetworkCredential($BindDN, $plainPassword)

$ldapConnection = New-Object System.DirectoryServices.Protocols.LdapConnection(
    (New-Object System.DirectoryServices.Protocols.LdapDirectoryIdentifier($LdapServer, $Port))
)
$ldapConnection.Credential = $credential
$ldapConnection.AuthType = [System.DirectoryServices.Protocols.AuthType]::Basic
$ldapConnection.SessionOptions.ProtocolVersion = 3
if ($UseTls) {
    $ldapConnection.SessionOptions.SecureSocketLayer = $true
}

try {
    # Passer $credential explicitement à Bind() plutôt que de compter uniquement sur la
    # propriété .Credential — sur l'implémentation .NET/Linux (native OpenLDAP), Bind() sans
    # argument ne reprend pas toujours fiablement le credential déjà assigné.
    $ldapConnection.Bind($credential)
}
catch {
    Write-Host "ERREUR LDAP : $($_.Exception.Message)" -ForegroundColor Red
    Write-Host "DN utilisé : [$BindDN]" -ForegroundColor Yellow
    exit 1
}
finally {
    Remove-Variable plainPassword -ErrorAction SilentlyContinue
}

Write-Host "Connecté à $LdapServer`:$Port (TLS: $UseTls)" -ForegroundColor Green

# --- Filtre : une "application" = un groupe dont le cn correspond à un des AppIds fournis ---
$appFilterParts = ($AppIds | ForEach-Object { "(cn=$_)" }) -join ""
$applicationSearchFilter = "(&(objectClass=$AppObjectClass)(|$appFilterParts))"

Write-Host "Filtre LDAP applications : $applicationSearchFilter"

# Tableau typé explicitement AVANT l'appel à New-Object : un littéral @(...) passé directement
# comme argument d'un paramètre constructeur "params string[]" ne se marshalle pas correctement
# ici (vérifié : la liste d'attributs demandée est silencieusement ignorée, rien ne revient).
[string[]]$searchAttributes = @("cn", "description", "uniqueMember")

$searchRequest = New-Object System.DirectoryServices.Protocols.SearchRequest(
    $BaseDN,
    $applicationSearchFilter,
    [System.DirectoryServices.Protocols.SearchScope]::Subtree,
    $searchAttributes
)

$searchResponse = $ldapConnection.SendRequest($searchRequest)
Write-Host "Applications trouvées : $($searchResponse.Entries.Count)"

$resultArray = [System.Collections.ArrayList]::new()

foreach ($appEntry in $searchResponse.Entries) {

    $appName        = $appEntry.Attributes["cn"][0]
    $appDescription = if ($appEntry.Attributes["description"]) { $appEntry.Attributes["description"][0] } else { "" }

    Write-Host "-- Application: $appName ($($appEntry.DistinguishedName))"

    # --- Rôles = sous-groupes situés un niveau sous l'application ---
    $roleSearchRequest = New-Object System.DirectoryServices.Protocols.SearchRequest(
        $appEntry.DistinguishedName,
        "(objectClass=$RoleObjectClass)",
        [System.DirectoryServices.Protocols.SearchScope]::OneLevel,
        $searchAttributes
    )

    $roleSearchResponse = $ldapConnection.SendRequest($roleSearchRequest)
    Write-Host "   Rôles trouvés : $($roleSearchResponse.Entries.Count)"

    if ($roleSearchResponse.Entries.Count -eq 0) {
        # Application sans sous-rôle : on garde quand même une ligne pour ne pas la perdre du rapport
        [void]$resultArray.Add([PSCustomObject]@{
            Application     = $appName
            AppDescription  = $appDescription
            Role            = ""
            RoleDescription = ""
            MemberCount     = if ($appEntry.Attributes["uniqueMember"]) { $appEntry.Attributes["uniqueMember"].Count } else { 0 }
        })
        continue
    }

    foreach ($roleEntry in $roleSearchResponse.Entries) {
        [void]$resultArray.Add([PSCustomObject]@{
            Application     = $appName
            AppDescription  = $appDescription
            Role            = $roleEntry.Attributes["cn"][0]
            RoleDescription = if ($roleEntry.Attributes["description"]) { $roleEntry.Attributes["description"][0] } else { "" }
            MemberCount     = if ($roleEntry.Attributes["uniqueMember"]) { $roleEntry.Attributes["uniqueMember"].Count } else { 0 }
        })
    }
}

$resultArray |
    Sort-Object Application, Role |
    Export-Csv $OutputCsv -NoTypeInformation -Encoding UTF8

Write-Host ""
Write-Host "=== Export terminé : $OutputCsv ($($resultArray.Count) lignes) ===" -ForegroundColor Green
