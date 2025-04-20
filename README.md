# 🛡️ Discord CVE Bot

Un bot Discord qui surveille les vulnérabilités CVE et informe automatiquement dans des salons textuels organisés par technologie.

## ✅ Fonctionnalités

- Récupération automatique des dernières CVE depuis l’API officielle de la NVD.
- Création de salons Discord selon les catégories détectées (`windows`, `php`, `cisco`, etc.).
- Ping du rôle `@alert-cve` pour les failles critiques (CVSS ≥ 7).
- Résumé automatique des failles toutes les 6h.
- Commandes **slash** simples et efficaces.
- Fallback vers `#autres_cve` si aucune catégorie ne correspond.

## 🚀 Installation

### 1. Cloner le projet

```bash
git clone https://github.com/ton-repo/discord-cve-bot.git
cd discord-cve-bot
```

### 2. Installer les dépendances

```bash
pip install discord.py python-dotenv requests
```

### 3. Créer le fichier `.env`

```env
DISCORD_TOKEN=TON_TOKEN_DISCORD
NVD_API_KEY=TA_CLÉ_API_NVD
```

Tu peux obtenir une clé API gratuite ici : [nvd.nist.gov](https://nvd.nist.gov/developers/request-an-api-key)

### 4. Lancer le bot

```bash
python bot.py
```

## 💬 Commandes Slash disponibles

| Commande               | Description |
|------------------------|-------------|
| `/force`               | Analyse les 3 derniers jours (cache utilisé) |
| `/force_all <jours>`   | Analyse toutes les CVE des X derniers jours (ignore le cache) |
| `/ajout_categorie <mot>` | Ajoute un mot-clé à la liste des catégories |
| `/status`              | Dernière date de vérification |
| `/cve_info <CVE-ID>`   | Détail d’une CVE spécifique |
| `/aide`                | Affiche l’aide |

## 🗂 Fichiers importants

| Fichier               | Rôle |
|-----------------------|------|
| `bot.py`              | Script principal |
| `categories.json`     | Liste des mots-clés surveillés |
| `cve_cache.json`      | Liste des CVE déjà traitées |
| `.env`                | Jeton Discord + API Key NVD |

## 📦 Exemple de `.gitignore`

```gitignore
.env
__pycache__/
*.pyc
cve_cache.json
```

---

Déployé et prêt à défendre ton serveur des vulnérabilités 👨‍💻🛡️
