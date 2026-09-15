<#
.SYNOPSIS
    Lance l'audit contre le serveur de démo public forumsys.com (lecture seule, schéma LDAP
    standard groupOfUniqueNames/uniqueMember — valeurs par défaut du script, pas besoin de les
    préciser). Pratique pour tester sans annuaire à disposition.

.NOTES
    Popup 1 (identifiant) : cn=read-only-admin,dc=example,dc=com
    Popup 1 (mot de passe) : password
    Popup 2 (applications) : scientists / mathematicians / chemists
#>

& (Join-Path $PSScriptRoot "Get-LdapAppRoleAudit.ps1") `
    -LdapServer "ldap.forumsys.com" `
    -Port 389 `
    -UseTls:$false `
    -BaseDN "dc=example,dc=com" `
    -OutputCsv (Join-Path $PSScriptRoot "LDAP-App-Role-Audit-ForumSys.csv")
