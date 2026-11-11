# RECON OSINT V4

Outil Python modulaire de reconnaissance OSINT encadrée et d'analyse locale. Python 3.10+ ; aucune dépendance externe à l'exécution.

## Modules

- **Certificate Transparency** : collecte passive via crt.sh, uniquement si `crtsh` figure dans `allowed_sources`.
- **DNS** : résolution A/AAAA via le résolveur du système, uniquement si `dns_enabled=true` et avec `--confirm-authorized`.
- **HTTP headers** : une seule requête GET sur `/` à la racine, sans crawl, uniquement si `active_http_enabled=true` et avec `--confirm-authorized`. Les redirections doivent rester dans le périmètre.
- **JavaScript** : analyse statique hors ligne de fichiers locaux ; extrait chemins/endpoints et noms de paramètres. Signale des motifs ressemblant à des secrets sans jamais reproduire leur valeur.
- **Rapports** : JSON et Markdown.

## Installation Windows PowerShell

```powershell
py -3 -m venv .venv
.\.venv\Scripts\Activate.ps1
python -m pip install -e .
```

## Exemples

Mode Meesho verrouillé (aucune collecte réseau avec la configuration initiale) :

```powershell
python main.py --profile meesho_root --config config.json --modules all --out reports
```

Analyse JavaScript locale (hors ligne) :

```powershell
python main.py --profile meesho_root --config config.json --modules js --js fixtures/js/sample.js --out reports
```

Profil de laboratoire : remplacer `example.com` par un domaine détenu ou explicitement autorisé. Examiner les options avant activation. Les modules DNS et HTTP nécessitent aussi la confirmation explicite :

```powershell
python main.py --profile lab --config config.json --domain example.com --modules dns,headers --confirm-authorized --out reports
```

## Sécurité et limites

- Le programme ne réalise ni exploitation, ni fuzzing, ni brute force, ni test de charge, ni crawl de site.
- Le profil `meesho_root` reste passif, racine uniquement et avec `allowed_sources: []`. Ne pas l'élargir sans autorisation écrite et précise du programme de bug bounty.
- `lab` est un modèle d'exemple, pas une autorisation. Configurez uniquement vos actifs ou ceux couverts par une autorisation explicite.
- Le module HTTP effectue une seule requête GET à `/`, pas un audit exhaustif. Les observations de headers sont des pistes, pas des vulnérabilités confirmées.
- Le module JavaScript analyse les fichiers déjà présents localement ; il ne télécharge aucun script du domaine.
- CT reflète des certificats publics, qui peuvent être historiques, et ne prouve ni disponibilité ni propriété opérationnelle d'un hôte.

## Tests hors ligne

```powershell
python -m unittest discover -s tests -v
```
