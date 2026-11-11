# RECON OSINT V4.1

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

## Lancer l'orchestrateur

`--run-integrations` demande l'orchestration. Chaque outil doit également figurer dans `enabled_tools` du profil. Les outils externes de reconnaissance nécessitent `--confirm-authorized`. Par défaut, tous les outils sont désactivés.

Exemple de profil de laboratoire, uniquement pour un domaine détenu ou couvert par une autorisation écrite :

```json
{
  "root_domain": "example.com",
  "include_subdomains": true,
  "mode": "authorized_lab",
  "integrations_disabled": false,
  "allow_passive_integrations": true,
  "enabled_tools": ["subfinder", "gau", "dnsx", "httpx"],
  "dns_enabled": true,
  "active_http_enabled": true,
  "active_crawl_enabled": false,
  "max_results": 100,
  "max_hosts": 10,
  "max_urls": 200,
  "max_web_targets": 3
}
```

Après configuration du domaine et validation de l'autorisation :

```powershell
python main.py --profile lab --config config.json --modules js --run-integrations --confirm-authorized --out reports
```

Katana reste désactivé tant que `active_crawl_enabled` n'est pas explicitement activé. Active-le uniquement avec une autorisation couvrant le crawl, un débit convenu et un périmètre de noms d'hôte précis.

### Analyse locale du code

Semgrep nécessite un fichier ou un dossier de règles local. Gitleaks utilise ses règles intégrées :

```powershell
python main.py --profile lab --run-integrations --source-dir .\mon-projet --semgrep-config .\rules\ --out reports
```

Ajoute `semgrep` et/ou `gitleaks` à `enabled_tools`. Ces modules analysent uniquement le chemin local fourni et n'effectuent pas de reconnaissance réseau.

## Verrouillage du profil Meesho

Le profil `meesho_root` de ce dépôt utilise `integrations_disabled: true`, `enabled_tools: []` et `allow_passive_integrations: false`. Le kill switch du code bloque les outils externes de ce profil même si `enabled_tools` est modifié accidentellement. Il n'effectue aucun scan Meesho. Les règles du programme de bug bounty restent la référence : le domaine racine ne donne pas automatiquement l'autorisation de tester des sous-domaines ou d'utiliser des scanners automatisés.

## Sécurité et limites

- Aucun module d'exploitation, brute force, fuzzing, test de charge ou DoS n'est orchestré.
- Subfinder et gau interrogent des services tiers ; ils restent désactivés tant que le profil ne les autorise pas explicitement.
- dnsx, httpx et Katana ne s'exécutent que dans un profil non passif, avec les interrupteurs propres au module et `--confirm-authorized`. Pour httpx, les entrées et résultats sont limités à HTTPS/443 lorsque `https_only=true`.
- Les hôtes et URL renvoyés par les outils sont revalidés contre le domaine du profil avant réutilisation. Les résultats HTTP et Katana hors périmètre sont exclus des données structurées du rapport.
- Katana est limité à la profondeur 2, un worker, un input à la fois, 1 requête/seconde, 20 requêtes/minute et 30 secondes. Ces plafonds ne garantissent pas l'absence d'impact : respecte les règles de l'actif.
- Les observations sont des pistes et non des vulnérabilités confirmées ; les vérifier manuellement avant tout rapport.
- Semgrep et Gitleaks analysent uniquement des fichiers/dossiers locaux fournis par l'utilisateur.

## Tests hors ligne

```powershell
python -m unittest discover -s tests -v
```
