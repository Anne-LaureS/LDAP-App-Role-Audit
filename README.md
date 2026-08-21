# 🔍 LDAP App/Role Audit

![PowerShell](https://img.shields.io/badge/PowerShell-5391FE?style=for-the-badge&logo=powershell&logoColor=white)
![LDAP](https://img.shields.io/badge/LDAP-IAM%20Audit-0d1117?style=for-the-badge)
![Windows](https://img.shields.io/badge/Windows%20only-0078D6?style=for-the-badge&logo=windows&logoColor=white)

Script PowerShell interrogeant un annuaire LDAP pour produire un export CSV
Application / Rôle / Description — utile pour un audit d'accès applicatifs (IAM/GRC) :
qui a accès à quoi, via quel rôle. Authentification et sélection des applications via
2 popups Windows Forms.

⚠️ **Windows uniquement** — `System.Windows.Forms` (les 2 popups) n'existe pas sous Linux/macOS.

## 🎯 Ce que ça fait

1. **Popup 1** : identifiant (DN) + mot de passe → authentification LDAP (LDAPS par défaut)
2. **Popup 2** : un ou plusieurs identifiants d'application à interroger (1 par ligne)
3. Recherche des groupes ("applications") correspondant à ces identifiants
4. Pour chaque application, recherche ses sous-groupes ("rôles")
5. Export CSV trié : nom de l'application, sa description, chacun de ses rôles avec sa
   description et son nombre de membres

Schéma utilisé : `groupOfUniqueNames` (RFC 2256, standard), pas un schéma propriétaire —
`-AppObjectClass`/`-RoleObjectClass` permettent d'adapter aux classes réelles de votre annuaire.

## 🚀 Utilisation

```powershell
.\Get-LdapAppRoleAudit.ps1 -LdapServer "votre-ldap.exemple.com" -BaseDN "ou=Applications,dc=exemple,dc=com"
```

Les 2 popups s'ouvrent ensuite pour l'authentification et la sélection des applications.

### Démo testable contre un serveur public

```powershell
.\Get-LdapAppRoleAudit.ps1 -LdapServer "ldap.forumsys.com" -Port 389 -UseTls:$false -BaseDN "dc=example,dc=com"
```

Identifiants à saisir dans les popups (serveur de démo public en lecture seule, voir
[forumsys.com](https://www.forumsys.com/tutorials/integration-how-to/ldap/online-ldap-test-server/)) :

| Popup | Champ | Valeur |
|---|---|---|
| 1 — Login | Identifiant (DN) | `cn=read-only-admin,dc=example,dc=com` |
| 1 — Login | Mot de passe | `password` |
| 2 — Applications | (une par ligne) | `scientists`, `mathematicians`, `chemists` |

### Exemple de sortie

[`sample-output.csv`](sample-output.csv) — export réel obtenu contre le serveur de démo
ci-dessus :

| Application | AppDescription | Role | RoleDescription | MemberCount |
|---|---|---|---|---|
| Chemists | | | | 4 |
| Mathematicians | | | | 5 |
| Scientists | | Italians | | 1 |

`MemberCount` = nombre de membres (`uniqueMember`) de cette application/rôle dans l'annuaire —
ex: le rôle `Italians` sous `Scientists` a 1 membre.

## 🔐 Sécurité

- **LDAPS par défaut** (`-UseTls`, activé par défaut) — un bind simple non chiffré transmet
  l'identifiant et le mot de passe en clair sur le réseau, interceptable par quiconque peut
  observer le trafic. `-UseTls:$false` n'existe que pour tester contre le serveur public
  ci-dessus, qui ne supporte plus aucune variante de TLS actuelle — jamais à reproduire contre
  un annuaire de production.
- **Mot de passe saisi via un champ masqué** (`UseSystemPasswordChar`), jamais en argument de
  ligne de commande en clair.

## ⚠️ Précautions si vous adaptez ce script

- **Conversion `SecureString` → texte clair** (si vous repassez par un paramètre au lieu du
  popup) : utiliser `Marshal.PtrToStringBSTR`, pas `PtrToStringAuto` — ce dernier lit mal le
  préfixe de longueur du BSTR sur .NET/Linux et tronque silencieusement le mot de passe
  (`"password"` devient `"p"`, sans erreur visible).
- **Listes d'attributs LDAP à retourner** : typer le tableau explicitement
  (`[string[]]$attrs = @("cn", "description")`) avant de l'utiliser comme paramètre `params
  string[]` d'un constructeur .NET (ex: `SearchRequest`). Un littéral `@(...)` passé
  directement en argument peut être silencieusement ignoré selon la plateforme — le filtre
  s'exécute sans erreur, mais aucun attribut n'est retourné.

La logique de recherche LDAP a été testée de bout en bout (bind, recherche, export CSV) contre
le serveur public ci-dessus avant publication.
