<#
.SYNOPSIS
    Interroge un annuaire LDAP pour produire un export CSV Application / Rôle / Description,
    utile pour des audits d'accès applicatifs (IAM/GRC). Authentification et sélection des
    applications via 2 popups Windows Forms.

.DESCRIPTION
    Popup 1 : identifiant + mot de passe (authentification LDAP).
    Popup 2 : un ou plusieurs identifiants d'application à interroger (1 par ligne).

    Recherche ensuite, sous une base DN donnée, les groupes correspondant aux identifiants
    saisis, puis pour chacun, recherche ses sous-groupes (assimilés ici à des rôles), et
    exporte le tout en CSV.

    Schéma utilisé ici : objectClass standard `groupOfUniqueNames` (RFC 2256), pas un schéma
    propriétaire — à adapter aux object classes/attributs réels de votre annuaire (ex:
    remplacer -AppObjectClass par la classe applicative de votre organisation).

    Popups System.Windows.Forms — PowerShell 5.1 ou 7+.

.PARAMETER LdapServer
    Nom d'hôte du serveur LDAP.

.PARAMETER Port
    Port LDAP. 636 (LDAPS) par défaut — voir la note sécurité ci-dessous.

.PARAMETER UseTls
    Utilise LDAPS (chiffré). Désactiver uniquement contre un serveur de test qui ne le supporte
    pas (voir note sécurité) — ne jamais désactiver contre un annuaire de production.

.PARAMETER BaseDN
    Base DN sous laquelle chercher les applications.

.PARAMETER AppObjectClass
    objectClass identifiant une "application" dans votre annuaire. `groupOfUniqueNames` par
    défaut (générique) — à remplacer par la classe propre à votre organisation le cas échéant.
    Contre Active Directory, une "application" modélisée en OU (rôles = groupes à l'intérieur)
    utilise `organizationalUnit`.

.PARAMETER MemberAttribute
    Nom de l'attribut multi-valué listant les membres d'une application/d'un rôle.
    `uniqueMember` par défaut (RFC 2256, `groupOfUniqueNames`). Contre Active Directory, utiliser
    `member` (attribut des groupes de sécurité AD).

.PARAMETER AppNameAttribute
    Attribut portant le nom d'une application, utilisé pour le filtre de recherche ET pour la
    colonne Application du CSV. `cn` par défaut (groupes). À changer en `ou` si -AppObjectClass
    est `organizationalUnit` : une OU n'a pas d'attribut `cn`, son nom est porté par `ou`.

.EXAMPLE
    # Démo contre le serveur de test public ldap.forumsys.com (lecture seule) — voir
    # "NOTE SÉCURITÉ" plus bas pour -UseTls:$false. Dans le popup login, saisir :
    #   Identifiant : cn=read-only-admin,dc=example,dc=com
    #   Mot de passe : password
    # Dans le popup applications, saisir (1 par ligne) : scientists / mathematicians / chemists
    .\Get-LdapAppRoleAudit.ps1 -LdapServer "ldap.forumsys.com" -Port 389 -UseTls:$false -BaseDN "dc=example,dc=com"

.EXAMPLE
    # Contre un vrai Active Directory : application = groupe (membres directs), pas de rôle.
    .\Get-LdapAppRoleAudit.ps1 -LdapServer "dc1.society.local" -BaseDN "OU=Applications,DC=society,DC=local" `
        -AppObjectClass "group" -RoleObjectClass "group" -MemberAttribute "member"

    # Application = OU contenant des groupes-rôles (organigramme app/rôles) : une OU n'a pas de
    # cn, d'où -AppNameAttribute "ou".
    .\Get-LdapAppRoleAudit.ps1 -LdapServer "dc1.society.local" -BaseDN "OU=Applications,DC=society,DC=local" `
        -AppObjectClass "organizationalUnit" -AppNameAttribute "ou" -RoleObjectClass "group" -MemberAttribute "member"

.NOTES
    NOTE SÉCURITÉ — pourquoi LDAPS par défaut :
    L'identifiant saisi au popup 1 détermine le mode d'authentification (voir plus bas) : au
    format "DOMAINE\utilisateur", Negotiate (NTLM/Kerberos) protège le mot de passe par
    challenge-response même sans TLS ; au format DN/UPN, bind simple (Basic) — le mot de passe
    part alors en clair sur le réseau sans TLS, interceptable par quiconque peut sniffer le
    trafic (switch compromis, ARP spoofing, proxy intermédiaire). Dans tous les cas, sans TLS le
    reste de la session (requêtes, résultats — ici des données d'accès applicatifs) circule aussi
    en clair. LDAPS (636) ou StartTLS chiffrent toute la session. Ce script utilise LDAPS par
    défaut ; -UseTls:$false n'existe que pour tester contre le serveur de démo public
    ldap.forumsys.com (son certificat LDAPS est invalide) — ne jamais désactiver TLS contre un
    annuaire de production.
#>

[CmdletBinding()]
param(
    [Parameter(Mandatory)]
    [string]$LdapServer,

    [int]$Port = 636,

    [bool]$UseTls = $true,

    [Parameter(Mandatory)]
    [string]$BaseDN,

    [string]$AppObjectClass = "groupOfUniqueNames",
    [string]$RoleObjectClass = "groupOfUniqueNames",
    [string]$MemberAttribute = "uniqueMember",
    [string]$AppNameAttribute = "cn",

    [string]$OutputCsv = (Join-Path $PSScriptRoot "LDAP_Applications_Roles_Audit.csv")
)

Add-Type -AssemblyName System.DirectoryServices.Protocols
Add-Type -AssemblyName System.Windows.Forms
Add-Type -AssemblyName System.Drawing

function Get-MemberNames {
    # uniqueMember renvoie des DN complets (ex: "uid=curie,dc=example,dc=com"), pas des noms
    # lisibles. On extrait la valeur du premier RDN (avant la 1ère virgule, après le "=")
    # plutôt que de faire une recherche LDAP supplémentaire par membre — plus rapide, suffisant
    # pour identifier qui est qui dans le CSV.
    #
    # Pas de type [string[]] sur le paramètre : System.DirectoryServices.Protocols renvoie
    # certains attributs (dont uniqueMember, selon le serveur) en byte[] plutôt qu'en string.
    # Si on force [string[]], PowerShell convertit chaque byte[] en sa représentation décimale
    # espacée ("117 105 100 61...") au lieu du texte — d'où des chiffres au lieu des lettres
    # dans le CSV. On détecte et décode explicitement le byte[] en UTF-8 à la place.
    param($MemberDNs)

    if (-not $MemberDNs) { return "" }

    ($MemberDNs | ForEach-Object {
        $dn = if ($_ -is [byte[]]) {
            [System.Text.Encoding]::UTF8.GetString($_)
        } else {
            [string]$_
        }
        ($dn -split ',')[0] -replace '^[^=]+=', ''
    }) -join "; "
}

###############################################################
# POPUP 1 — LOGIN
###############################################################

$loginForm = New-Object System.Windows.Forms.Form
$loginForm.Text = "LDAP App/Role Audit — Authentification"
$loginForm.Size = New-Object System.Drawing.Size(420, 200)
$loginForm.StartPosition = "CenterScreen"

$lblUser = New-Object System.Windows.Forms.Label
$lblUser.Text = "Identifiant (DN) :"
$lblUser.Location = New-Object System.Drawing.Point(10, 20)
$lblUser.AutoSize = $true
$loginForm.Controls.Add($lblUser)

$txtUser = New-Object System.Windows.Forms.TextBox
$txtUser.Location = New-Object System.Drawing.Point(150, 20)
$txtUser.Width = 240
$loginForm.Controls.Add($txtUser)

$lblPwd = New-Object System.Windows.Forms.Label
$lblPwd.Text = "Mot de passe :"
$lblPwd.Location = New-Object System.Drawing.Point(10, 60)
$lblPwd.AutoSize = $true
$loginForm.Controls.Add($lblPwd)

$txtPwd = New-Object System.Windows.Forms.TextBox
$txtPwd.Location = New-Object System.Drawing.Point(150, 60)
$txtPwd.Width = 240
$txtPwd.UseSystemPasswordChar = $true
$loginForm.Controls.Add($txtPwd)

$btnLogin = New-Object System.Windows.Forms.Button
$btnLogin.Text = "Connexion"
$btnLogin.Location = New-Object System.Drawing.Point(150, 110)
$btnLogin.Add_Click({
    $loginForm.DialogResult = [System.Windows.Forms.DialogResult]::OK
    $loginForm.Close()
})
$loginForm.Controls.Add($btnLogin)
$loginForm.AcceptButton = $btnLogin

if ($loginForm.ShowDialog() -ne [System.Windows.Forms.DialogResult]::OK) {
    exit
}

$BindDN = $txtUser.Text.Trim()
$plainPassword = $txtPwd.Text

if (-not $BindDN) {
    Write-Host "Identifiant manquant." -ForegroundColor Red
    exit
}
if (-not $plainPassword) {
    Write-Host "Mot de passe manquant." -ForegroundColor Red
    exit
}

###############################################################
# POPUP 2 — SÉLECTION DES APPLICATIONS
###############################################################

$appForm = New-Object System.Windows.Forms.Form
$appForm.Text = "LDAP App/Role Audit — Applications à interroger"
$appForm.Size = New-Object System.Drawing.Size(500, 350)
$appForm.StartPosition = "CenterScreen"

$lblApp = New-Object System.Windows.Forms.Label
$lblApp.Text = "Saisir un ou plusieurs identifiants d'application (1 par ligne) :"
$lblApp.Location = New-Object System.Drawing.Point(10, 10)
$lblApp.AutoSize = $true
$appForm.Controls.Add($lblApp)

$txtApp = New-Object System.Windows.Forms.TextBox
$txtApp.Multiline = $true
$txtApp.ScrollBars = "Vertical"
$txtApp.Location = New-Object System.Drawing.Point(10, 40)
$txtApp.Size = New-Object System.Drawing.Size(460, 220)
$appForm.Controls.Add($txtApp)

$btnApp = New-Object System.Windows.Forms.Button
$btnApp.Text = "Valider"
$btnApp.Location = New-Object System.Drawing.Point(200, 270)
$btnApp.Add_Click({
    $appForm.DialogResult = [System.Windows.Forms.DialogResult]::OK
    $appForm.Close()
})
$appForm.Controls.Add($btnApp)
$appForm.AcceptButton = $btnApp

if ($appForm.ShowDialog() -ne [System.Windows.Forms.DialogResult]::OK) {
    exit
}

$AppIds = $txtApp.Lines | ForEach-Object { $_.Trim() } | Where-Object { $_ -ne "" }

if ($AppIds.Count -eq 0) {
    Write-Host "Aucune application saisie." -ForegroundColor Red
    exit
}

###############################################################
# CONNEXION LDAP
###############################################################

# Format NetBIOS "DOMAINE\utilisateur" (ex: SOCIETY\Administrateur) : impossible en bind simple
# contre Active Directory (non supporté), il faut Negotiate (NTLM/Kerberos) et un Domain séparé.
# DN complet ou UPN (ex: cn=...,dc=... comme sur forumsys.com, ou user@domaine) : bind simple,
# compatible AD ET OpenLDAP.
if ($BindDN -match '^([^\\]+)\\(.+)$') {
    $credential = New-Object System.Net.NetworkCredential($matches[2], $plainPassword, $matches[1])
    $authType = [System.DirectoryServices.Protocols.AuthType]::Negotiate
} else {
    $credential = New-Object System.Net.NetworkCredential($BindDN, $plainPassword)
    $authType = [System.DirectoryServices.Protocols.AuthType]::Basic
}
Remove-Variable plainPassword

$ldapConnection = New-Object System.DirectoryServices.Protocols.LdapConnection(
    (New-Object System.DirectoryServices.Protocols.LdapDirectoryIdentifier($LdapServer, $Port))
)
$ldapConnection.Credential = $credential
$ldapConnection.AuthType = $authType
$ldapConnection.SessionOptions.ProtocolVersion = 3
if ($UseTls) {
    $ldapConnection.SessionOptions.SecureSocketLayer = $true
}

try {
    # Passer $credential explicitement à Bind() plutôt que de compter uniquement sur la
    # propriété .Credential — sur l'implémentation .NET/Linux (native OpenLDAP), Bind() sans
    # argument ne reprend pas toujours fiablement le credential déjà assigné. Gardé ici même si
    # ce script cible Windows, pour rester cohérent avec la version testée du code.
    $ldapConnection.Bind($credential)
}
catch {
    Write-Host "ERREUR LDAP : $($_.Exception.Message)" -ForegroundColor Red
    Write-Host "DN utilisé : [$BindDN]" -ForegroundColor Yellow
    exit 1
}

Write-Host "Connecté à $LdapServer`:$Port (TLS: $UseTls)" -ForegroundColor Green

###############################################################
# RECHERCHE APPLICATIONS
###############################################################

# --- Filtre : une "application" = un objet dont AppNameAttribute correspond à un des AppIds saisis ---
$appFilterParts = ($AppIds | ForEach-Object { "($AppNameAttribute=$_)" }) -join ""
$applicationSearchFilter = "(&(objectClass=$AppObjectClass)(|$appFilterParts))"

Write-Host "Filtre LDAP applications : $applicationSearchFilter"

# Tableau typé explicitement AVANT l'appel à New-Object : un littéral @(...) passé directement
# comme argument d'un paramètre constructeur "params string[]" ne se marshalle pas correctement
# ici (vérifié : la liste d'attributs demandée est silencieusement ignorée, rien ne revient).
[string[]]$searchAttributes = @("cn", $AppNameAttribute, "description", $MemberAttribute) | Select-Object -Unique

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

    $appName        = $appEntry.Attributes[$AppNameAttribute][0]
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

    # Toujours une ligne pour l'appartenance DIRECTE à l'application elle-même (Role vide) —
    # même quand l'application a aussi des rôles. Sans ça, les membres directs d'une
    # application qui a par ailleurs des sous-rôles étaient silencieusement absents du CSV
    # (vérifié : "Scientists" a 4 membres directs en plus du rôle "Italians" — un rôle en
    # moins n'était pas grave, mais des accès en moins sur un outil d'audit, si).
    [void]$resultArray.Add([PSCustomObject]@{
        Application     = $appName
        AppDescription  = $appDescription
        Role            = ""
        RoleDescription = ""
        MemberCount     = if ($appEntry.Attributes[$MemberAttribute]) { $appEntry.Attributes[$MemberAttribute].Count } else { 0 }
        Members         = Get-MemberNames -MemberDNs $appEntry.Attributes[$MemberAttribute]
    })

    foreach ($roleEntry in $roleSearchResponse.Entries) {
        [void]$resultArray.Add([PSCustomObject]@{
            Application     = $appName
            AppDescription  = $appDescription
            Role            = $roleEntry.Attributes["cn"][0]
            RoleDescription = if ($roleEntry.Attributes["description"]) { $roleEntry.Attributes["description"][0] } else { "" }
            MemberCount     = if ($roleEntry.Attributes[$MemberAttribute]) { $roleEntry.Attributes[$MemberAttribute].Count } else { 0 }
            Members         = Get-MemberNames -MemberDNs $roleEntry.Attributes[$MemberAttribute]
        })
    }
}

$resultArray |
    Sort-Object Application, Role |
    Export-Csv $OutputCsv -NoTypeInformation -Encoding UTF8

Write-Host ""
Write-Host "=== Export terminé : $OutputCsv ($($resultArray.Count) lignes) ===" -ForegroundColor Green
