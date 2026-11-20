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
git clone <ce dépôt> && cd debian-host-audit
docker build -t debian-host-audit:0.1.0 .

mkdir -p reports
docker run --rm --privileged --pid=host \
  -v /:/host:ro -v "$PWD/reports:/reports" \
  debian-host-audit:0.1.0
```

`summary.md` s'affiche sur la sortie standard. Tout est écrit dans `reports/<hostname>_<horodatage UTC>/`. Les fichiers appartiennent au propriétaire de `reports/` et ne sont lisibles que par lui.

**Pour un agent**, demander le JSON sur la sortie standard (les journaux partent sur la sortie d'erreur) :

```bash
docker run --rm --privileged --pid=host -v /:/host:ro debian-host-audit:0.1.0 --json > audit.json
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
  --images running|all|none   images à scanner (par défaut : celles des conteneurs en marche)
  --max-images N              au plus N images (la couverture indique alors "partial")
  --docker-socket CHEMIN      par défaut : /host/run/docker.sock
  --json                      summary.json sur la sortie standard au lieu de summary.md
  --fail-on SÉVÉRITÉ          sortie 2 si un constat atteint ou dépasse SÉVÉRITÉ
  --offline                   ne jamais télécharger la base Trivy (construire avec EMBED_TRIVY_DB=1)
  --version
```

Codes de sortie : `0` rapport produit · `1` erreur préalable (option ou montage manquant) · `2` seuil `--fail-on` atteint.

## Le rapport

`summary.json` (`schema_version: 1`) :

| Champ | Contenu |
|---|---|
| `run` | hostname, OS, horodatage, durée, versions des outils, étapes |
| `coverage[]` | une entrée par contrôle : `ok` / `partial` / `failed` / `skipped`, avec la raison et la durée |
| `coverage_complete` | passe à `false` dès qu'un contrôle n'est pas `ok`. **À lire en premier.** |
| `witness` | la preuve que Lynis a audité l'hôte et non le conteneur (voir plus bas) |
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
2. Ils s'exécutent depuis le système de fichiers de l'image et y écrivent leurs rapports, en passant par `/proc/<pid du conteneur>/root`. **Rien n'est écrit sur le disque de l'hôte audité.** Une seule exception : Lynis crée dans le `/tmp` de l'hôte des fichiers temporaires de courte durée, qu'il supprime.
3. **Trivy** ne parcourt jamais le système de fichiers de l'hôte. Il scanne une copie minimale de `os-release` et du `status` de dpkg, ce qui prend quelques secondes, même sur un hôte qui porte des téraoctets de données. Les images sont lues via le socket Docker.
4. **Contrôle témoin.** L'image est elle aussi en Debian 13, donc « l'OS est Debian 13 » ne prouve rien. La synthèse compare le hostname vu par Lynis à celui de l'hôte, et le nombre de paquets compté par Lynis à un plancher que l'image ne peut pas atteindre. Si l'un des deux échoue, les constats Lynis sont écartés et sa couverture passe à `failed`.

Les vérifications préalables refusent de lancer l'audit sans `-v /:/host:ro`, `--pid=host` ou `--privileged`, plutôt que de rendre un rapport sur le mauvais système.

## Auditer plusieurs VM

```bash
# copie l'image par SSH (sans registre), l'exécute, rapatrie <hôte>.json en local
scripts/audit-remote.sh --ship-image vm1 vm2 admin@vm3 -- all --max-images 20
```

Les fichiers bruts restent sur chaque hôte, dans `~/host-audit-reports/`. Ajouter `--sudo` si l'utilisateur SSH n'est pas dans le groupe `docker`.

## Sécurité

- **`--privileged --pid=host` avec `/` monté, c'est root sur l'hôte.** C'est inhérent à l'audit d'un hôte depuis un conteneur. Lancer l'image à la demande, avec `--rm`, et jamais comme service permanent.
- **L'image est un point de confiance de la chaîne d'approvisionnement.** Chaque composant est épinglé par version et SHA-256 dans le `Dockerfile`, et l'image de base par empreinte. La signature Sigstore de l'archive Trivy a été vérifiée avant l'épinglage : les binaires publiés de Trivy ont été compromis en 2026. Revérifier à chaque montée de version :
  ```bash
  cosign verify-blob --bundle trivy_<v>_Linux-64bit.tar.gz.sigstore.json \
    --certificate-identity-regexp '^https://github.com/aquasecurity/trivy/' \
    --certificate-oidc-issuer https://token.actions.githubusercontent.com trivy_<v>_Linux-64bit.tar.gz
  ```
- **Les rapports sont sensibles.** Ils décrivent précisément comment attaquer l'hôte. Ils sont écrits lisibles par leur seul propriétaire (`0700`/`0600`) ; ne pas les laisser traîner dans un endroit public.
- **Lecture seule par construction.** Ni `apt update`, ni installation de paquet, ni changement de configuration. Les mises à jour en attente sont lues dans le cache apt local, et un constat prévient quand ce cache a plus de 7 jours.

## Limites

- **Conçu pour Debian 13 (trixie).** Les autres versions de Debian fonctionnent en grande partie, avec un avertissement. Les autres distributions ne sont pas prises en charge.
- **docker-bench-security 1.6.1 est sa dernière version publiée (2023).** Il implémente le référentiel CIS Docker 1.6, et certains contrôles sont en retard sur les versions récentes de Docker Engine.
- **Un seul démon Docker** est audité, celui du socket par défaut. Docker rootless et `userns-remap` n'ont pas été testés.
- **Trivy télécharge sa base de vulnérabilités** (~80 Mo) à chaque passage. Pour un hôte isolé, construire avec `--build-arg EMBED_TRIVY_DB=1` et passer `--offline`. La base embarquée vieillit, il faut donc reconstruire régulièrement.
- **La détection du pare-feu** cherche une politique entrante en refus par défaut (nftables `hook input … policy drop`, `iptables -P INPUT DROP`, ou ufw `deny (incoming)`). Elle n'évalue pas les règles une par une. Les ports publiés par Docker contournent la chaîne INPUT : ils font l'objet d'un constat à part.

## Développement

```bash
python3 -m unittest discover -s tests          # bibliothèque standard uniquement
shellcheck -S warning bin/audit lib/collect-host.sh scripts/audit-remote.sh
```

Pour monter un composant de version, changer `*_VERSION` et `*_SHA256` dans le `Dockerfile` dans le même commit.

## Licence

MIT, voir [LICENSE](LICENSE). L'image redistribue sans modification :
- Lynis, sous **GPL-3.0** : son code source, ce sont les scripts shell eux-mêmes, dans `/opt/lynis` ;
- docker-bench-security et Trivy, sous **Apache-2.0**.

Leurs textes de licence se trouvent dans `/usr/share/doc/third-party/` à l'intérieur de l'image.
