<#
.SYNOPSIS
    Rejoue les audits du lab AD sans aucune popup : les 20 applications (membres directs), les 20
    applications avec résolution des groupes imbriqués, puis les 2 audits ciblés du README.

.DESCRIPTION
    Enchaîne Get-LdapAppRoleAudit.ps1 en mode non interactif (-Credential et -AppIds) : les
    identifiants ne sont demandés qu'une seule fois pour les 4 audits. Produit :

      Audit_Applications_OU.csv                  20 applications, membres directs
      Audit_Applications_OU_ResolveNested.csv    20 applications, personnes (accès directs et
                                                 indirects) : c'est celui qu'utilise
                                                 IAM-Access-Recertification
      Audit_CRM.csv, Audit_Comptabilite.csv      audits ciblés sur une application
      LDAP_Applications_Roles_Audit.csv          copie du premier (nom historique du repo)

    Ce DC de lab n'a pas de certificat LDAPS (-Port 389 -UseTls:$false) : ne jamais faire cela
    contre un annuaire de production (voir README, section Sécurité).

.PARAMETER Credential
    Identifiants du bind (SOCIETY\Administrateur). Demandés une seule fois si omis.

.PARAMETER LdapServer
    Contrôleur de domaine. DC1.society.local par défaut.

.PARAMETER AppIds
    Applications à auditer pour les 2 audits complets (les 20 du lab par défaut).

.EXAMPLE
    .\Invoke-LabAudit.ps1
#>

[CmdletBinding()]
param(
    [System.Management.Automation.PSCredential]$Credential,

    [string]$LdapServer = "DC1.society.local",

    [string[]]$AppIds = @(
        "CRM", "ERP", "SIRH", "Comptabilite", "RH", "Juridique", "Marketing", "Support-N3",
        "CoreBanking", "Credit", "KYC-LCBFT", "Paiements-SEPA", "Tresorerie-Marches", "Risques",
        "Monetique", "Achats", "ITSM", "SecOps", "DevOps", "Helpdesk"
    )
)

if (-not $Credential) {
    $Credential = Get-Credential -Message "Identifiants pour le bind sur $LdapServer (ex: SOCIETY\Administrateur)"
}
if (-not $Credential) {
    Write-Host "ERREUR : aucun identifiant fourni." -ForegroundColor Red
    exit 1
}

$audit = Join-Path $PSScriptRoot "Get-LdapAppRoleAudit.ps1"
$common = @{
    LdapServer       = $LdapServer
    Port             = 389
    UseTls           = $false
    BaseDN           = "OU=Applications,DC=society,DC=local"
    AppObjectClass   = "organizationalUnit"
    AppNameAttribute = "ou"
    RoleObjectClass  = "group"
    MemberAttribute  = "member"
    Credential       = $Credential
}

$runs = @(
    @{ Label = "20 applications (membres directs)"; Params = @{ AppIds = $AppIds; OutputCsv = (Join-Path $PSScriptRoot "Audit_Applications_OU.csv") } }
    @{ Label = "20 applications (-ResolveNested)"; Params = @{ AppIds = $AppIds; ResolveNested = $true; OutputCsv = (Join-Path $PSScriptRoot "Audit_Applications_OU_ResolveNested.csv") } }
    @{ Label = "CRM (audit ciblé)"; Params = @{ AppIds = @("CRM"); OutputCsv = (Join-Path $PSScriptRoot "Audit_CRM.csv") } }
    @{ Label = "Comptabilite (audit ciblé)"; Params = @{ AppIds = @("Comptabilite"); OutputCsv = (Join-Path $PSScriptRoot "Audit_Comptabilite.csv") } }
)

foreach ($run in $runs) {
    Write-Host "`n>>> $($run.Label)" -ForegroundColor Cyan
    $auditParams = $common + $run.Params
    & $audit @auditParams
    if ($LASTEXITCODE -and $LASTEXITCODE -ne 0) {
        Write-Host "Audit interrompu (code $LASTEXITCODE) : $($run.Label)" -ForegroundColor Red
        exit $LASTEXITCODE
    }
}

Copy-Item (Join-Path $PSScriptRoot "Audit_Applications_OU.csv") (Join-Path $PSScriptRoot "LDAP_Applications_Roles_Audit.csv") -Force
Write-Host "`n=== 4 audits terminés ===" -ForegroundColor Green
