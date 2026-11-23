# debian-host-audit

*[English version](README.md)*

Une image, une commande, un rapport normalisé : un **audit de sécurité en lecture seule d'un hôte Debian 13**. Il est conçu pour qu'un humain *ou un agent IA* ait toute la situation dans un seul fichier.

L'image embarque trois outils libres reconnus et une série de contrôles maison. Elle les exécute contre **l'hôte**, et non contre le conteneur, puis fusionne le tout dans `summary.json` et `summary.md`, avec une seule forme de constat et une seule échelle de sévérité.

| Couche | Outil | Ce qu'il couvre |
|---|---|---|
| Durcissement de l'hôte | [Lynis](https://github.com/CISOfy/lynis) 3.1.7 | ~260 tests : noyau, démarrage, authentification, PAM, droits des fichiers, services, journalisation… |
| Essentiels de l'hôte | contrôles maison | configuration SSH effective, comptes en uid 0, groupes équivalents à root (`docker`), pare-feu en refus par défaut, services en écoute exposés, ports Docker publiés sur toutes les interfaces, mises à jour de sécurité en attente, unattended-upgrades, redémarrage en attente, unités en échec, options de montage de `/tmp` |
| Docker | [docker-bench-security](https://github.com/docker/docker-bench-security) 1.6.1 | référentiel CIS Docker : configuration du démon, fichiers, images, conteneurs en marche |
| Vulnérabilités | [Trivy](https://github.com/aquasecurity/trivy) 0.76.2 | CVE des paquets Debian de l'hôte et des images de conteneurs |

## Pourquoi

Ces outils sont bons, mais chacun a son format de sortie et sa propre notion de sévérité. Aucun ne prévient quand il a audité la mauvaise cible sans le dire. Une plateforme lourde (Wazuh, OpenVAS) est disproportionnée pour l'audit ponctuel de quelques VM. Ce projet est la couche fine entre les deux.

## Démarrage rapide

```bash
docker pull ghcr.io/aurelienfeignon/debian-host-audit:0.1
# vérifier qu'elle a été construite par la CI de ce dépôt, depuis un commit étiqueté
gh attestation verify oci://ghcr.io/aurelienfeignon/debian-host-audit:0.1 --owner aurelienFeignon

mkdir -p reports
docker run --rm --privileged --pid=host \
  -v /:/host:ro -v "$PWD/reports:/reports" \
  ghcr.io/aurelienfeignon/debian-host-audit:0.1
```

Étiquettes : `0.1.2` (exacte), `0.1` (dernier correctif), `latest`. Pour un outil qui tourne en root, mieux vaut épingler l'empreinte affichée par `docker pull` : `ghcr.io/aurelienfeignon/debian-host-audit@sha256:…`. Les images sont en linux/amd64, avec un SBOM et une attestation de provenance signée.

Ou la construire soi-même :

```bash
git clone https://github.com/aurelienFeignon/debian-host-audit && cd debian-host-audit
docker build -t debian-host-audit:0.1.2 .
```

`summary.md` s'affiche sur la sortie standard. Tout est écrit dans `reports/<hostname>_<horodatage UTC>/`, sous l'identité du propriétaire de `reports/` (pas en root), et lisible par lui seul.

**Pour un agent**, demander le JSON sur la sortie standard (les journaux partent sur la sortie d'erreur) :

```bash
docker run --rm --privileged --pid=host -v /:/host:ro debian-host-audit:0.1.2 --json > audit.json
jq '.coverage_complete, .counts, [.findings[] | select(.severity=="critical" or .severity=="high")]' audit.json
```

Sur un hôte chargé, un passage complet prend 3 à 5 minutes, plus 3 s à 2 min par image scannée.

## Utilisation

```
debian-host-audit [ÉTAPE...] [OPTIONS]

Étapes (par défaut : all)
  host      Lynis + contrôles maison de l'hôte
  docker    docker-bench-security (sauté si Docker est absent)
  vulns     scan Trivy des paquets Debian de l'hôte
  images    scan Trivy des images de conteneurs

Options
  --images running|all|none   images à scanner (par défaut : celles des conteneurs en marche ; l'image de l'audit elle-même est écartée)
  --max-images N              au plus N images (la couverture indique alors "partial")
  --docker-socket CHEMIN      par défaut : /host/run/docker.sock
  --json                      summary.json sur la sortie standard au lieu de summary.md
  --fail-on SÉVÉRITÉ          sortie 2 si un constat atteint ou dépasse SÉVÉRITÉ
  --offline                   ne jamais télécharger la base Trivy (construire avec EMBED_TRIVY_DB=1)
  --version
```

Codes de sortie : `0` rapport produit · `1` erreur (option ou montage manquant, option invalide, synthèse en échec) · `2` rapport produit et seuil `--fail-on` atteint. Les options sont validées avant le début de l'audit.

## Le rapport

`summary.json` (`schema_version: 1`) :

| Champ | Contenu |
|---|---|
| `run` | hostname, OS, horodatage, durée, versions des outils, étapes |
| `coverage[]` | une entrée par contrôle : `ok` / `partial` / `failed` / `skipped`, avec la raison et la durée |
| `coverage_complete` | passe à `false` dès qu'un contrôle n'est pas `ok`. **À lire en premier.** |
| `witness` | la preuve que Lynis a audité l'hôte et non le conteneur (voir plus bas). Le collecteur subit le même contrôle. |
| `host` | indice de durcissement Lynis, décompte docker-bench, faits collectés (écoutes, groupes, réglages sshd, noyaux…) |
| `counts` | nombre de constats par sévérité |
| `findings[]` | `{id, source, severity, category, title, evidence, remediation, references}`, triés par sévérité |
| `vulnerabilities[]` | par cible (paquets de l'hôte, chaque image) : décomptes par sévérité, décomptes corrigeables, critiques et élevées sans correctif, et la liste complète des CVE critiques et élevées corrigeables |

L'échelle de sévérité est `critical > high > medium > low > info`. Correspondances :

- **Lynis** : un avertissement devient `medium`, une suggestion `low`.
- **docker-bench** : un `WARN` devient `medium`. Il monte à `high` quand le contrôle rompt directement l'isolation : conteneurs privilégiés, socket Docker monté dans un conteneur, espace de noms de l'hôte partagé, dossiers sensibles de l'hôte montés, registres non sûrs, démon TCP sans authentification.
- **Trivy** : un constat par cible qui porte des CVE critiques ou élevées *corrigeables*, à la pire sévérité trouvée. Les CVE sans correctif disponible (`affected`, `fix_deferred`, `will_not_fix`) donnent un seul constat `info`, puisqu'il n'y a encore rien à mettre à jour.
- **Contrôles maison** : chacun fixe son niveau. Un uid 0 autre que root donne `critical` ; un membre du groupe docker, `PermitRootLogin yes` ou une mise à jour de sécurité en attente donnent `high`, etc.

`raw/` conserve la sortie brute de chaque outil, pour vérifier n'importe quel constat.

## Fonctionnement

Le conteneur ne fait que **livrer** les outils. Il ne s'audite pas lui-même.

1. **Lynis, docker-bench et le collecteur maison s'exécutent dans les espaces de noms de l'hôte** (`nsenter -t 1 -m -u -i -n -p`), avec les binaires de l'hôte. Un Lynis lancé dans un conteneur ordinaire audite le conteneur, et son rapport paraît propre.
2. Ils s'exécutent depuis le système de fichiers de l'image et écrivent dans un **dossier de travail situé dans le système de fichiers propre au conteneur** (`/var/lib/dha-work`), qu'ils atteignent depuis l'espace de noms de l'hôte via `/proc/<pid du conteneur>/root`. Aucun utilisateur de l'hôte n'a accès à ce dossier : rien de ce qu'il y planterait (un lien symbolique, par exemple) ne peut rediriger ces écritures root vers l'hôte. **Rien n'est écrit sur le disque de l'hôte audité.**
   - Lynis est corrigé (3 lignes, [`build/patch-lynis.sh`](build/patch-lynis.sh)) pour que ses fichiers temporaires et son fichier PID suivent `LYNIS_TMPDIR` dans ce dossier de travail, au lieu du `/tmp` et du `/var/run` de l'hôte. Le build échoue si ces lignes changent en amont.
3. **Trivy** ne parcourt jamais le système de fichiers de l'hôte. Il scanne une copie minimale de `os-release` et du `status` de dpkg, lue via l'espace de noms de l'hôte, ce qui prend quelques secondes, même sur un hôte qui porte des téraoctets de données. Les images sont lues via le socket Docker. Trivy sort en 0 avec un résultat vide quand il ne reconnaît pas l'OS : la synthèse exige donc un OS détecté et un nombre de paquets cohérent avec dpkg. Sinon, le contrôle est `failed`, et non propre.
4. **Contrôles témoins.** L'image est elle aussi en Debian 13, donc « l'OS est Debian 13 » ne prouve rien. La synthèse compare le hostname vu par Lynis (forme courte) à celui de l'hôte lu via le montage `/host`, qui ne dépend pas des espaces de noms traversés. Elle compare aussi le nombre de paquets compté par Lynis à un plancher que l'image ne peut pas atteindre. Si l'un des deux échoue, les constats Lynis sont écartés et sa couverture passe à `failed`. Le hostname vu par le collecteur subit le même contrôle.
5. **Livraison.** À la fin, le dossier de travail est copié dans `/reports/<nom>`, avec l'uid et le gid du propriétaire de `/reports` et toutes les capacités retirées, dans un dossier qui ne doit pas déjà exister. Il n'y a aucun `chown` récursif en root.

Les vérifications préalables refusent de lancer l'audit sans `-v /:/host:ro`, `--pid=host` ou `--privileged`, plutôt que de rendre un rapport sur le mauvais système. Le contrôle de `--pid=host` compare les espaces de noms de montage : `--init` ne le trompe pas.

## Auditer plusieurs VM

```bash
# chaque hôte tire ghcr.io/…/debian-host-audit:<majeure.mineure de VERSION> (IMAGE= pour une autre),
# l'exécute ; <hôte>.json est rapatrié en local, lisible du seul propriétaire
scripts/audit-remote.sh vm1 vm2 admin@vm3 -- all --max-images 20

# ou, avec une image construite en local et des hôtes sans accès au registre
scripts/audit-remote.sh --ship-image vm1 vm2
```

L'image par défaut est retéléchargée à chaque passage : un hôte n'audite jamais avec le correctif plus ancien tiré la fois précédente, et la ligne de synthèse affiche la version de l'outil réellement exécutée. Un `IMAGE=` explicite ou `--ship-image` s'emploie tel qu'il se trouve sur l'hôte. Les fichiers bruts restent sur chaque hôte, dans `~/host-audit-reports/`. Ajouter `--sudo` si l'utilisateur SSH n'est pas dans le groupe `docker` ; il faut alors un sudo sans mot de passe, puisque ssh tourne sans tty. Un hôte en échec n'arrête jamais les autres. Code de sortie : `0` tous les rapports produits, `2` tous produits et au moins un a atteint `--fail-on`, `1` au moins un hôte en échec.

## Sécurité

- **`--privileged --pid=host` avec `/` monté, c'est root sur l'hôte.** C'est inhérent à l'audit d'un hôte depuis un conteneur. Lancer l'image à la demande, avec `--rm`, et jamais comme service permanent.
- **L'image est un point de confiance de la chaîne d'approvisionnement.** Chaque composant est épinglé par version et SHA-256 dans le `Dockerfile`, et l'image de base par empreinte. La signature Sigstore de l'archive Trivy a été vérifiée avant l'épinglage : les binaires publiés de Trivy ont été compromis en 2026. Revérifier à chaque montée de version :
  ```bash
  cosign verify-blob --bundle trivy_<v>_Linux-64bit.tar.gz.sigstore.json \
    --certificate-identity-regexp '^https://github.com/aquasecurity/trivy/' \
    --certificate-oidc-issuer https://token.actions.githubusercontent.com trivy_<v>_Linux-64bit.tar.gz
  ```
- **Les rapports sont sensibles.** Ils décrivent précisément comment attaquer l'hôte. Ils sont créés lisibles par leur seul propriétaire dès le départ (`umask 077`), et restent dans le conteneur jusqu'à la fin du passage. Ne pas les laisser traîner dans un endroit public.
- **Lecture seule par construction.** Ni `apt update`, ni installation de paquet, ni changement de configuration. Les mises à jour en attente sont lues dans le cache apt local, et un constat prévient quand ce cache a plus de 7 jours.

## Autres distributions

Construit et testé sur Debian 13 (trixie). Ailleurs, chaque partie se dégrade de façon explicite, sans produire de faux résultat :

| Partie | Ubuntu / famille Debian | RHEL, Rocky, Alma, Fedora, Alpine, Arch… |
|---|---|---|
| Lynis | ✅ | ✅ (Lynis est multi-distribution) |
| docker-bench | ✅ | ✅ |
| Trivy, images | ✅ | ✅ |
| Trivy, paquets de l'hôte | ✅ | ⏭️ `skipped` (pas de dpkg), visible dans `coverage` |
| Contrôles maison | ✅ | ⚠️ partiel : les contrôles fondés sur apt (mises à jour en attente, unattended-upgrades) ne sont pas évalués, le reste tourne |

Un contrôle qui ne peut pas tourner sur un hôte est absent des constats. Il n'est jamais signalé comme un problème.

## Limites

- **docker-bench-security 1.6.1 est sa dernière version publiée (2023).** Il implémente le référentiel CIS Docker 1.6, et certains contrôles sont en retard sur les versions récentes de Docker Engine.
- **Un seul démon Docker** est audité, celui du socket par défaut. Docker rootless et `userns-remap` n'ont pas été testés.
- **Trivy télécharge sa base de vulnérabilités** (~80 Mo) à chaque passage. Pour un hôte isolé, construire avec `--build-arg EMBED_TRIVY_DB=1` et passer `--offline`. La base embarquée vieillit, il faut donc reconstruire régulièrement.
- **La détection du pare-feu** cherche une politique entrante en refus par défaut (nftables `hook input … policy drop`, `iptables -P INPUT DROP`, ou ufw `deny (incoming)`). Elle n'évalue pas les règles une par une. Les ports publiés par Docker contournent la chaîne INPUT : ils font l'objet d'un constat à part.

## Développement

```bash
python3 -m unittest discover -s tests          # bibliothèque standard uniquement
shellcheck -S warning bin/audit lib/collect-host.sh scripts/audit-remote.sh build/patch-lynis.sh
```

Pour monter un composant de version, changer `*_VERSION` et `*_SHA256` dans le `Dockerfile` dans le même commit.

La CI (`.github/workflows/ci.yml`) lance les tests unitaires et shellcheck, construit l'image, puis **audite le runner GitHub lui-même**. Elle échoue si le témoin, ou l'un des contrôles Lynis, maison, docker-bench ou trivy-host, n'est pas `ok`. Pour publier une version : monter `VERSION`, faire le commit, puis pousser l'étiquette correspondante (`git tag v0.1.2 && git push origin v0.1.2`). Si l'étiquette ne correspond pas à `VERSION`, la publication échoue.

## Licence

MIT, voir [LICENSE](LICENSE). L'image redistribue :
- Lynis, sous **GPL-3.0**, **modifié** : 3 lignes, pour que les fichiers temporaires et PID suivent `LYNIS_TMPDIR`. La modification est [`build/patch-lynis.sh`](build/patch-lynis.sh), et le code modifié, ce sont les scripts shell eux-mêmes, dans `/opt/lynis` ;
- docker-bench-security et Trivy, sous **Apache-2.0**, sans modification.

Leurs textes de licence se trouvent dans `/usr/share/doc/third-party/` à l'intérieur de l'image.
