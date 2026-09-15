<#
.SYNOPSIS
    Lance l'audit contre le lab Active Directory (DC1.society.local) : applications modélisées
    en OU avec groupes-rôles imbriqués (member/ou, pas uniqueMember/cn).

.NOTES
    Popup 1 (identifiant) : SOCIETY\Administrateur
    Popup 2 (applications) : CRM / ERP / SIRH / Comptabilite / RH / Juridique / Marketing / Support-N3

    Ce DC de lab n'a pas de certificat LDAPS configuré, d'où -Port 389 -UseTls:$false — ne jamais
    faire ça contre un annuaire de production (voir README, section Sécurité).
#>

& (Join-Path $PSScriptRoot "Get-LdapAppRoleAudit.ps1") `
    -LdapServer "DC1.society.local" `
    -Port 389 `
    -UseTls:$false `
    -BaseDN "OU=Applications,DC=society,DC=local" `
    -AppObjectClass "organizationalUnit" `
    -AppNameAttribute "ou" `
    -RoleObjectClass "group" `
    -MemberAttribute "member" `
    -OutputCsv (Join-Path $PSScriptRoot "LDAP_Applications_Roles_Audit.csv")
