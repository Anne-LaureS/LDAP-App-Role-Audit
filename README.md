# 🔍 LDAP App/Role Audit

![PowerShell](https://img.shields.io/badge/PowerShell-5391FE?style=for-the-badge&logo=powershell&logoColor=white)
![LDAP](https://img.shields.io/badge/LDAP-IAM%20Audit-0d1117?style=for-the-badge)

Script PowerShell interrogeant un annuaire LDAP pour produire un export CSV
Application / Rôle / Description — utile pour un audit d'accès applicatifs (IAM/GRC) :
qui a accès à quoi, via quel rôle.

## 🎯 Ce que ça fait

1. Bind LDAP authentifié (LDAPS par défaut)
2. Recherche des groupes ("applications") correspondant à une liste d'identifiants fournie
3. Pour chaque application, recherche ses sous-groupes ("rôles")
4. Export CSV trié, une ligne par couple application/rôle

Schéma utilisé : `groupOfUniqueNames` (RFC 2256, standard), pas un schéma propriétaire —
`-AppObjectClass`/`-RoleObjectClass` permettent d'adapter aux classes réelles de votre annuaire.

## 🚀 Utilisation

```powershell
.\Get-LdapAppRoleAudit.ps1 `
    -LdapServer "votre-ldap.exemple.com" `
    -BaseDN "ou=Applications,dc=exemple,dc=com" `
    -BindDN "cn=service-account,dc=exemple,dc=com" `
    -AppIds "APP001","APP002"
```

### Démo testable contre un serveur public

```powershell
.\Get-LdapAppRoleAudit.ps1 `
    -LdapServer "ldap.forumsys.com" -Port 389 -UseTls:$false `
    -BaseDN "dc=example,dc=com" `
    -BindDN "cn=read-only-admin,dc=example,dc=com" `
    -AppIds "scientists","mathematicians","chemists"
```

(mot de passe : `password` — c'est un serveur de démo public en lecture seule, voir
[forumsys.com](https://www.forumsys.com/tutorials/integration-how-to/ldap/online-ldap-test-server/))

## 🔐 Sécurité

- **LDAPS par défaut** (`-UseTls`, activé par défaut) — un bind simple non chiffré transmet
  l'identifiant et le mot de passe en clair sur le réseau, interceptable par quiconque peut
  observer le trafic. `-UseTls:$false` n'existe que pour tester contre le serveur public
  ci-dessus, qui ne supporte plus aucune variante de TLS actuelle — jamais à reproduire contre
  un annuaire de production.
- **Mot de passe en `SecureString`**, jamais en argument de ligne de commande en clair.

## ⚠️ Précautions si vous adaptez ce script

- **Conversion `SecureString` → texte clair** : utiliser `Marshal.PtrToStringBSTR`, pas
  `PtrToStringAuto` — ce dernier lit mal le préfixe de longueur du BSTR sur .NET/Linux et
  tronque silencieusement le mot de passe (`"password"` devient `"p"`, sans erreur visible).
- **Listes d'attributs LDAP à retourner** : typer le tableau explicitement
  (`[string[]]$attrs = @("cn", "description")`) avant de l'utiliser comme paramètre `params
  string[]` d'un constructeur .NET (ex: `SearchRequest`). Un littéral `@(...)` passé
  directement en argument peut être silencieusement ignoré selon la plateforme — le filtre
  s'exécute sans erreur, mais aucun attribut n'est retourné.

Testé de bout en bout (bind, recherche, export CSV) contre le serveur LDAP public ci-dessus
avant publication.
