# 🤖 CVE Discord Bot - Veille Cyber

Un bot Discord open-source pour la **surveillance automatique des vulnérabilités CVE**.

Il classe, notifie et organise les failles en créant automatiquement des salons textuels classés par technologies.

---

## 🚀 Fonctionnalités principales

- ✨ **Récupère automatiquement les CVE depuis [nvd.nist.gov](https://nvd.nist.gov)**
- 🌐 **Création automatique de salons textuels** par technologie (“php”, “windows”, etc.)
- ⚡ **Ping d'un rôle `@alert-cve`** en cas de criticité élevée (CVSS >= 7)
- 🔍 **Analyse régulière toutes les 6h** et publication d'un résumé dans `#cve-resume-quotidien`
- ❓ **Catégories personnalisables** via `categories.json`
- ✉️ **Commandes Discord pour interagir et forcer les analyses**

---

## 🧰 Librairies Python requises

Installez les dépendances avec :
```bash
pip install discord.py python-dotenv requests
```

---

## 🗂️ Fichiers importants

| Fichier | Rôle |
|--------|------|
| `bot.py` | Le cœur du bot (le script principal) |
| `categories.json` | Liste des mots-clés technos à surveiller |
| `cve_cache.json` | Empêche les doublons (cache local) |
| `.env` | Contient vos clés sécurisées |

---

## 🔁 Mises à jour automatiques

- Le bot lance une vérification **toutes les 6h**.
- Le résumé s'affiche dans `#cve-resume-quotidien`
- Les CVE critiques pingent le rôle `@alert-cve`
- Les CVE sans mot-clé connu vont dans `#autres_cve`

---

## 🧭 Commandes disponibles

| Commande | Description |
|---------|-------------|
| `!force` | Analyse des CVE des 3 derniers jours |
| `!force_all <jours>` | Analyse des CVE jusqu'à 1000 jours (ignore le cache) |
| `!ajout_categorie <mot>` | Ajoute une techno personnalisée à `categories.json` |
| `!status` | Affiche la date de la dernière vérification |
| `!aide` | Affiche ce menu |

---

## 🚀 Fonctionnement technique

- Le bot utilise l'API NVD v2.0 avec filtrage sur les dates
- Utilisation de `ThreadPoolExecutor` pour accélérer les requêtes multiples
- Analyse des titres/descriptions CVE pour détection des technos
- Réduction de la charge Discord via envoi en morceaux (1990 char max)

---

## 📊 Exemple de message CVE
```
🔴 CVE-2025-12345 - Critique (CVSS 9.8)
Buffer overflow in XYZ
🔗 https://nvd.nist.gov/vuln/detail/CVE-2025-12345
```

---

## ⚠️ Permissions recommandées
- Envoyer des messages
- Créer des salons
- Gérer les rôles (pour `@alert-cve`)

---

## 🌟 Améliorations possibles
- Site web de consultation des CVE
- Base de données persistante avec historisation
- Interaction Webhook/Slash Commands

---

## 🙏 Merci !
Ce projet est en constante amélioration. Forkez-le, testez-le, et surtout : restez à jour en cybersécurité !
