# RECON OSINT V4.2

Plateforme Python qui orchestre des outils open source spécialisés, normalise leurs résultats et applique un contrôle de périmètre avant leur intégration au rapport. Python 3.10+ ; les modules Python du projet utilisent la bibliothèque standard. Les exécutables externes sont facultatifs et doivent être installés séparément.

## Outils intégrés

| Outil | Fonction | Type |
|---|---|---|
| [Subfinder](https://github.com/projectdiscovery/subfinder) | Énumération passive de sous-domaines | Passif / sources tierces |
| [gau](https://github.com/lc/gau) | URL archivées (Wayback, Common Crawl, OTX, URLScan) | Passif / sources tierces |
| [dnsx](https://github.com/projectdiscovery/dnsx) | Résolution DNS A, AAAA et CNAME | Requête DNS |
| [httpx](https://github.com/projectdiscovery/httpx) | Statut HTTP, titre, technologies, serveur et IP | Requête HTTP |
| [Katana](https://github.com/projectdiscovery/katana) | Exploration limitée et extraction JavaScript | Crawl HTTP |
| [Semgrep](https://github.com/semgrep/semgrep) | Analyse statique du code local | Local |
| [Gitleaks](https://github.com/gitleaks/gitleaks) | Recherche de secrets dans un dépôt/dossier local | Local |

RECON OSINT ne réécrit pas ces outils : il vérifie leur présence dans `PATH` et leur signature CLI avant toute exécution (ce qui évite notamment de confondre le client HTTP Python `httpx` avec le scanner HTTP de ProjectDiscovery). Il lance des arguments prédéfinis sans shell, applique des délais, filtre les hôtes/URL hors périmètre et rassemble les sorties JSON/texte.

## Installation Python (Windows PowerShell)

```powershell
py -3 -m venv .venv
.\.venv\Scripts\Activate.ps1
python -m pip install -e .
```

Installe uniquement les exécutables nécessaires depuis les pages Releases officielles liées ci-dessus. Les outils ProjectDiscovery sont développés en Go et proposent des binaires Windows ; Gitleaks fournit également des binaires Windows. Semgrep s'installe séparément selon les prérequis de sa version et de ton environnement.

Vérifier les exécutables installés (ne lance aucun scan) :

```powershell
python main.py --profile lab --check-tools
```

## Cible universelle à chaque lancement

Le profil `lab` est un modèle universel : il ne fixe aucun domaine. À chaque exécution, RECON-OSINT demande une cible (domaine, URL HTTP(S), IPv4 ou IPv6), ou accepte `--target`. La cible saisie devient la racine exacte du périmètre pour cette exécution ; elle n'est pas enregistrée comme cible permanente.

Les sept adaptateurs sont activés dans le profil laboratoire : Subfinder, gau, DNSx, HTTPX, Katana, Semgrep et Gitleaks. Seuls les adaptateurs compatibles avec la cible et les données fournies sont exécutés. Pour une IP, Subfinder, gau et DNSx sont ignorés ; HTTPX et Katana peuvent examiner le service Web. Semgrep et Gitleaks nécessitent un dossier de code local. Les sous-domaines sont exclus par défaut ; ajoutez `--include-subdomains` uniquement lorsque l'autorisation les couvre.

Lancement interactif (la cible puis une confirmation d'autorisation seront demandées) :

```powershell
python main.py --profile lab --run-integrations --out reports
```

Pour saisir directement une cible :

```powershell
python main.py --profile lab --target https://example.org/app --run-integrations --out reports
```

Pour inclure les sous-domaines expressément autorisés :

```powershell
python main.py --profile lab --include-subdomains --run-integrations --out reports
```

Pour une IP privée d'un laboratoire que vous êtes autorisé à tester (HTB, VM ou réseau de test), ajoutez l'option explicite :

```powershell
python main.py --profile lab --target http://192.168.56.10:8080 --allow-private-target --run-integrations --out reports
```

Sans `--allow-private-target`, les connexions HTTP vers des IP non publiques sont bloquées. Les URL contenant des identifiants sont refusées ; les paramètres de requête et fragments sont supprimés des URL utilisées comme cible. Les intégrations réseau nécessitent une confirmation à chaque exécution, sauf si `--confirm-authorized` est fourni.

### Analyse locale du code

Semgrep nécessite un fichier ou un dossier de règles local. Gitleaks utilise ses règles intégrées :

```powershell
python main.py --profile lab --run-integrations --source-dir .\mon-projet --semgrep-config .\rules\ --out reports
```

Les analyses Semgrep et Gitleaks portent uniquement sur le chemin local fourni. Elles ne scannent pas le site Web distant.

## Verrouillage du profil Meesho

Le profil `meesho_root` de ce dépôt utilise `integrations_disabled: true`, `enabled_tools: []` et `allow_passive_integrations: false`. Le kill switch du code bloque les outils externes de ce profil même si `enabled_tools` est modifié accidentellement. Il n'effectue aucun scan Meesho. Les règles du programme de bug bounty restent la référence : le domaine racine ne donne pas automatiquement l'autorisation de tester des sous-domaines ou d'utiliser des scanners automatisés.

## Sécurité et limites

- Aucun module d'exploitation, brute force, fuzzing, test de charge ou DoS n'est orchestré.
- Subfinder et gau interrogent des services tiers ; leur utilisation est activée dans le profil lab mais reste soumise à la confirmation d'autorisation de chaque lancement.
- DNSx, HTTPX et Katana ne s'exécutent qu'après confirmation d'autorisation. Les URL sont limitées à l'hôte et au port saisis ; les IP privées nécessitent `--allow-private-target`.
- Les hôtes et URL renvoyés par les outils sont revalidés contre la cible de l'exécution avant réutilisation. Les sous-domaines ne sont inclus qu'avec `--include-subdomains`.
- Katana est limité à la profondeur 2, un worker, un input à la fois, 1 requête/seconde, 20 requêtes/minute et 30 secondes. Ces plafonds ne garantissent pas l'absence d'impact : respecte les règles de l'actif.
- Les observations sont des pistes et non des vulnérabilités confirmées ; les vérifier manuellement avant tout rapport.
- Semgrep et Gitleaks analysent uniquement des fichiers/dossiers locaux fournis par l'utilisateur.

## Tests hors ligne

```powershell
python -m unittest discover -s tests -v
```
