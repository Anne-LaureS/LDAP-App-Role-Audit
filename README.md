# 🔍 LDAP App/Role Audit

![PowerShell](https://img.shields.io/badge/PowerShell-5391FE?style=for-the-badge&logo=powershell&logoColor=white)
![LDAP](https://img.shields.io/badge/LDAP-IAM%20Audit-0d1117?style=for-the-badge)
![Windows](https://img.shields.io/badge/Windows%20only-0078D6?style=for-the-badge&logo=windows&logoColor=white)

Script PowerShell interrogeant un annuaire LDAP pour produire un export CSV
Application / Rôle / Description — utile pour un audit d'accès applicatifs (IAM/GRC) :
qui a accès à quoi, via quel rôle. Authentification et sélection des applications via
2 popups Windows Forms.

⚠️ **Windows uniquement** — `System.Windows.Forms` (les 2 popups) n'existe pas sous Linux/macOS.

## ⚙️ Ce que ça fait

1. **Popup 1** : identifiant (DN) + mot de passe → authentification LDAP (LDAPS par défaut)
2. **Popup 2** : un ou plusieurs identifiants d'application à interroger (1 par ligne)
3. Recherche des groupes ("applications") correspondant à ces identifiants
4. Pour chaque application, recherche ses sous-groupes ("rôles")
5. Export CSV trié : nom de l'application, sa description, chacun de ses rôles avec sa
   description et son nombre de membres

Schéma utilisé : `groupOfUniqueNames` (RFC 2256, standard), pas un schéma propriétaire —
`-AppObjectClass`/`-RoleObjectClass` permettent d'adapter aux classes réelles de votre annuaire.

## ▶️ Utilisation

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

[`LDAP_Applications_Roles_Audit.csv`](LDAP_Applications_Roles_Audit.csv) — export réel obtenu contre le serveur de démo
ci-dessus :

| Application | AppDescription | Role | RoleDescription | MemberCount | Members |
|---|---|---|---|---|---|
| Chemists | | | | 4 | curie; boyle; nobel; pasteur |
| Mathematicians | | | | 5 | euclid; riemann; euler; gauss; test |
| Scientists | | | | 4 | einstein; tesla; newton; galileo |
| Scientists | | Italians | | 1 | tesla |

Une ligne `Role` vide = accès direct à l'application elle-même (pas via un rôle spécifique).
`Scientists` a 2 lignes : 4 membres directs, et en plus `tesla` qui a aussi le rôle `Italians`.

- `MemberCount` = nombre de membres (`uniqueMember`) de cette application/rôle dans l'annuaire.
- `Members` = qui ils sont, extrait du DN de chaque membre (ex: `uid=curie,dc=example,dc=com`
  → `curie`) — pas de recherche LDAP supplémentaire par membre, juste le RDN.

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
- **Valeurs d'attributs multi-valeurs comme `uniqueMember`** : `System.DirectoryServices.Protocols`
  peut les renvoyer en `byte[]` plutôt qu'en texte selon le serveur/schéma. Si le paramètre
  d'une fonction est typé `[string[]]`, PowerShell convertit alors chaque `byte[]` en sa
  représentation décimale espacée (des chiffres) au lieu du texte attendu — sans erreur, juste
  un résultat silencieusement faux. Décoder explicitement en UTF-8 quand `$_ -is [byte[]]`
  (voir `Get-MemberNames` dans le script).
- **Accès direct à une application vs accès via un rôle** : quand une application a des
  sous-rôles, ne pas se limiter à eux — ses membres directs (`uniqueMember` sur l'entrée de
  l'application elle-même) sont un accès distinct, à exporter en plus, pas à la place. Une
  application avec des rôles peut très bien avoir aussi des membres directs (vérifié :
  `Scientists` a 4 membres directs, en plus du rôle `Italians` porté par 1 d'entre eux) — s'en
  tenir uniquement aux rôles sous-estime silencieusement les accès réels.

La logique de recherche LDAP a été testée de bout en bout (bind, recherche, export CSV) contre
le serveur public ci-dessus avant publication.
