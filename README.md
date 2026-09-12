# 🔍 LDAP App/Role Audit

![PowerShell](https://img.shields.io/badge/PowerShell-5391FE?style=for-the-badge&logo=powershell&logoColor=white)
![LDAP](https://img.shields.io/badge/LDAP-IAM%20Audit-0d1117?style=for-the-badge)

Script PowerShell interrogeant un annuaire LDAP pour produire un export CSV
Application / Rôle / Description — utile pour un audit d'accès applicatifs (IAM/GRC) :
qui a accès à quoi, via quel rôle. Authentification et sélection des applications via
2 popups Windows Forms (`System.Windows.Forms`).

Testé en deux temps : d'abord un premier passage rapide contre un serveur LDAP public (démo en
lecture seule), puis validé de bout en bout contre un vrai Active Directory sur un lab Windows
Server 2022 — voir les sections dédiées plus bas.

## ⚙️ Ce que ça fait

1. **Popup 1** : identifiant (DN) + mot de passe → authentification LDAP (LDAPS par défaut)
2. **Popup 2** : un ou plusieurs identifiants d'application à interroger (1 par ligne)
3. Recherche des groupes ("applications") correspondant à ces identifiants
4. Pour chaque application, recherche ses sous-groupes ("rôles")
5. Export CSV trié : nom de l'application, sa description, chacun de ses rôles avec sa
   description et son nombre de membres

Schéma utilisé par défaut : `groupOfUniqueNames`/`uniqueMember` (RFC 2256, standard OpenLDAP),
pas un schéma propriétaire — `-AppObjectClass`/`-RoleObjectClass`/`-MemberAttribute`/
`-AppNameAttribute` permettent d'adapter aux classes et attributs réels de votre annuaire (voir
Active Directory ci-dessous pour un exemple concret).

## ▶️ Utilisation

```powershell
.\Get-LdapAppRoleAudit.ps1 -LdapServer "votre-ldap.exemple.com" -BaseDN "ou=Applications,dc=exemple,dc=com"
```

Les 2 popups s'ouvrent ensuite pour l'authentification et la sélection des applications.

## 🧪 Validation : lab Active Directory (Windows Server 2022)

Scénario principal de test de ce script — un vrai contrôleur de domaine (VM Windows Server 2022,
`DC1`, domaine `society.local`, réseau isolé host-only/NAT, pas d'exposition externe), avec 8
applications et 21 utilisateurs de test, comptes cumulant plusieurs rôles/applications pour
vérifier la détection des recoupements d'accès — le genre de sur-privilège qu'un audit IAM doit
faire remonter.

AD utilise un schéma différent de `groupOfUniqueNames` : les groupes de sécurité portent leurs
membres dans `member` (pas `uniqueMember`), et une OU n'a pas d'attribut `cn` (son nom est dans
`ou`). Deux façons de modéliser une "application", selon comment elle est structurée dans votre
AD :

**Application = un groupe, avec des membres directs (pas de rôle) :**
```powershell
.\Get-LdapAppRoleAudit.ps1 -LdapServer "DC1.society.local" -BaseDN "OU=Applications,DC=society,DC=local" `
    -AppObjectClass "group" -RoleObjectClass "group" -MemberAttribute "member"
```

**Application = une OU contenant des groupes-rôles** (un groupe ne peut pas avoir d'objets
enfants dans AD, seule une OU le peut — donc ce schéma s'impose dès qu'une application a des
sous-rôles à interroger) :
```powershell
.\Get-LdapAppRoleAudit.ps1 -LdapServer "DC1.society.local" -BaseDN "OU=Applications,DC=society,DC=local" `
    -AppObjectClass "organizationalUnit" -AppNameAttribute "ou" -RoleObjectClass "group" -MemberAttribute "member"
```

Ce DC de lab n'ayant pas de certificat LDAPS configuré, le test réel a été fait avec
`-Port 389 -UseTls:$false` — acceptable ici (réseau isolé, comptes de test jetables), mais à ne
jamais faire contre un annuaire de production (voir Sécurité ci-dessous).

### Résultats réels

Les 8 applications du lab sont désormais toutes modélisées en OU avec groupes-rôles imbriqués
(la commande `-AppObjectClass "group"` ci-dessus reste utile pour un AD où une application n'a
pas de sous-rôles, mais ce n'est plus le cas dans ce lab).

[`Audit_Applications_OU.csv`](Audit_Applications_OU.csv) :

| Application | Role | MemberCount | Members |
|---|---|---|---|
| Comptabilite | | 0 | |
| Comptabilite | Comptabilite-Admin | 1 | jdupont |
| Comptabilite | Comptabilite-Consultant | 1 | mmartin |
| Comptabilite | Comptabilite-Standard | 3 | hlemoine; agarcia; pbernard |
| CRM | | 0 | |
| CRM | CRM-Admin | 1 | lrousseau |
| CRM | CRM-Lecture | 2 | tnoel; lrousseau |
| CRM | CRM-Support | 2 | fandre; wroux |
| ERP | | 0 | |
| ERP | ERP-Admin | 1 | hlemoine |
| ERP | ERP-Support | 1 | tnoel |
| ERP | ERP-Utilisateur | 4 | rmoreau; kdiallo; sfontaine; jdupont |
| Juridique | | 0 | |
| Juridique | Juridique-Admin | 1 | cbenali |
| Juridique | Juridique-Standard | 1 | vlefevre |
| Marketing | | 0 | |
| Marketing | Marketing-Consultant | 1 | tgirard |
| Marketing | Marketing-Owner | 1 | ymichel |
| Marketing | Marketing-Standard | 2 | opetit; nleroy |
| RH | | 0 | |
| RH | RH-Admin | 1 | rmoreau |
| RH | RH-Standard | 2 | kdiallo; sfontaine |
| SIRH | | 0 | |
| SIRH | SIRH-Admin | 1 | lrousseau |
| SIRH | SIRH-Lecture | 3 | agarcia; pbernard; mmartin |
| Support-N3 | | 0 | |
| Support-N3 | Support-N3-Admin | 1 | Bertrand Caron |
| Support-N3 | Support-N3-Standard | 2 | Julien Roche; Nadia Faure |

`lrousseau` cumule 3 rôles admin/lecture sur 2 applications distinctes (CRM + SIRH), `jdupont`
cumule Comptabilite-Admin et ERP-Utilisateur, `hlemoine` cumule Comptabilite-Standard et
ERP-Admin — exactement le type de recoupement qu'un audit d'accès applicatif doit détecter.

## 🌐 Démo rapide sans annuaire à soi

Pas d'AD/LDAP sous la main pour essayer le script ? Un serveur de démo public (lecture seule)
permet de le tester en 30 secondes :

```powershell
.\Get-LdapAppRoleAudit.ps1 -LdapServer "ldap.forumsys.com" -Port 389 -UseTls:$false -BaseDN "dc=example,dc=com"
```

Identifiants à saisir dans les popups (voir
[forumsys.com](https://www.forumsys.com/tutorials/integration-how-to/ldap/online-ldap-test-server/)) :

| Popup | Champ | Valeur |
|---|---|---|
| 1 — Login | Identifiant (DN) | `cn=read-only-admin,dc=example,dc=com` |
| 1 — Login | Mot de passe | `password` |
| 2 — Applications | (une par ligne) | `scientists`, `mathematicians`, `chemists` |

[`LDAP_Applications_Roles_Audit.csv`](LDAP_Applications_Roles_Audit.csv) — export réel obtenu
contre ce serveur :

| Application | AppDescription | Role | RoleDescription | MemberCount | Members |
|---|---|---|---|---|---|
| Chemists | | | | 4 | curie; boyle; nobel; pasteur |
| Mathematicians | | | | 5 | euclid; riemann; euler; gauss; test |
| Scientists | | | | 4 | einstein; tesla; newton; galileo |
| Scientists | | Italians | | 1 | tesla |

Une ligne `Role` vide = accès direct à l'application elle-même (pas via un rôle spécifique).
`Scientists` a 2 lignes : 4 membres directs, et en plus `tesla` qui a aussi le rôle `Italians`.

- `MemberCount` = nombre de membres (`-MemberAttribute`, `uniqueMember` par défaut) de cette
  application/rôle dans l'annuaire.
- `Members` = qui ils sont, extrait du DN de chaque membre (ex: `uid=curie,dc=example,dc=com`
  → `curie`) — pas de recherche LDAP supplémentaire par membre, juste le RDN.

## 🔐 Sécurité

- **LDAPS par défaut** (`-UseTls`, activé par défaut) — un bind simple non chiffré transmet
  l'identifiant et le mot de passe en clair sur le réseau, interceptable par quiconque peut
  observer le trafic. `-UseTls:$false` n'existe que pour tester contre le serveur de démo public
  ci-dessus (son certificat LDAPS est invalide) — ne jamais désactiver TLS contre un annuaire de
  production.
- **Mot de passe saisi via un champ masqué** (`UseSystemPasswordChar`), jamais en argument de
  ligne de commande en clair.

## ⚠️ Précautions si vous adaptez ce script

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
