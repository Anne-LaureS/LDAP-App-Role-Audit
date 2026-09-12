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

    ⚠️ Popups Windows Forms : ce script ne fonctionne que sous Windows (PowerShell 5.1 ou
    PowerShell 7+ sur Windows) — System.Windows.Forms n'existe pas sous Linux/macOS.

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

.EXAMPLE
    # Démo contre le serveur de test public ldap.forumsys.com (lecture seule) — voir
    # "NOTE SÉCURITÉ" plus bas pour -UseTls:$false. Dans le popup login, saisir :
    #   Identifiant : cn=read-only-admin,dc=example,dc=com
    #   Mot de passe : password
    # Dans le popup applications, saisir (1 par ligne) : scientists / mathematicians / chemists
    .\Get-LdapAppRoleAudit.ps1 -LdapServer "ldap.forumsys.com" -Port 389 -UseTls:$false -BaseDN "dc=example,dc=com"

.NOTES
    NOTE SÉCURITÉ — pourquoi LDAPS par défaut :
    Un bind LDAP simple (Basic) sur port 389 sans TLS transmet l'identifiant ET le mot de passe
    en clair sur le réseau — quiconque peut sniffer le trafic (switch compromis, ARP spoofing,
    proxy intermédiaire) récupère des identifiants valides. LDAPS (636) ou StartTLS chiffrent la
    session avant l'envoi des identifiants. Ce script utilise LDAPS par défaut ; -UseTls:$false
    n'existe que pour permettre de tester contre le serveur public ldap.forumsys.com, dont le
    certificat LDAPS (CN=ldap, O=TurnKey OpenLDAP, auto-signé) est expiré depuis le 19/02/2015 et
    ne correspond pas au nom d'hôte — la négociation TLS elle-même aboutit (vérifié : TLS 1.1
    accepté), mais LdapConnection.Bind() sous Windows refuse ce certificat invalide et échoue.
    Ce n'est donc pas une absence de support TLS côté serveur, mais un certificat de démo mort —
    -UseTls:$false n'est PAS le comportement à reproduire contre un annuaire réel dont le
    certificat est valide.
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

    [string]$OutputCsv = "LDAP_Applications_Roles_Audit.csv"
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

$credential = New-Object System.Net.NetworkCredential($BindDN, $plainPassword)
Remove-Variable plainPassword

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

# --- Filtre : une "application" = un groupe dont le cn correspond à un des AppIds saisis ---
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
        MemberCount     = if ($appEntry.Attributes["uniqueMember"]) { $appEntry.Attributes["uniqueMember"].Count } else { 0 }
        Members         = Get-MemberNames -MemberDNs $appEntry.Attributes["uniqueMember"]
    })

    foreach ($roleEntry in $roleSearchResponse.Entries) {
        [void]$resultArray.Add([PSCustomObject]@{
            Application     = $appName
            AppDescription  = $appDescription
            Role            = $roleEntry.Attributes["cn"][0]
            RoleDescription = if ($roleEntry.Attributes["description"]) { $roleEntry.Attributes["description"][0] } else { "" }
            MemberCount     = if ($roleEntry.Attributes["uniqueMember"]) { $roleEntry.Attributes["uniqueMember"].Count } else { 0 }
            Members         = Get-MemberNames -MemberDNs $roleEntry.Attributes["uniqueMember"]
        })
    }
}

$resultArray |
    Sort-Object Application, Role |
    Export-Csv $OutputCsv -NoTypeInformation -Encoding UTF8

Write-Host ""
Write-Host "=== Export terminé : $OutputCsv ($($resultArray.Count) lignes) ===" -ForegroundColor Green
