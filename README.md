# ☁️ Serveur de Synchronisation Tux-It (Back Go)

Ce dossier contient le serveur de synchronisation léger et ultra-performant écrit en **Go** pour sauvegarder et synchroniser vos notes Tux-It entre plusieurs appareils.

Il utilise **SQLite** pour stocker vos données de synchronisation et vos clés d'API, et dispose d'une superbe **console d'administration Web** pour gérer vos clés d'accès.

---

## Features

- **Ultra-léger & Rapide** : Binaire autonome compilé d'environ 5 Mo, consommation mémoire minimale (~5 Mo de RAM).
- **Base SQLite** : Stockage robuste dans une base SQLite unique (`data/postit.db`).
- **Authentification par Clé d'API** : Authentification par en-tête `Authorization: Bearer <clé_api>`.
- **Console d'Administration Web** : Disponible sous `/admin` pour créer et révoquer dynamiquement les clés d'API de vos clients.
- **Sécurisation Admin** : Protégé par un mot de passe administrateur défini dans l'environnement (`ADMIN_PASSWORD`).

---

## 🐳 Déploiement avec Docker (Recommandé)

Pour l'auto-héberger facilement sur un serveur ou un NAS :

1. Ouvrez [docker-compose.yml](docker-compose.yml) et configurez votre mot de passe d'administration (`ADMIN_PASSWORD`).
2. Lancez le conteneur :
   ```bash
   docker compose up --build -d
   ```
*Le serveur démarrera sur le port `8282` (http://localhost:8282). Les données SQLite seront persistées dans `./data/`.*

---

## 🚀 Lancement Manuel (Sans Docker)

Vous devez avoir Go (v1.22+) installé.

### Démarrage direct en développement :
```bash
export ADMIN_PASSWORD="mon_mot_de_passe_secret"
go run main.go
```
*Le serveur écoutera sur le port `8282`.*

### Compilation en un binaire autonome optimisé :
```bash
CGO_ENABLED=0 go build -ldflags="-w -s" -o tux-server main.go
./tux-server
```

---

## ⚙️ Configuration du client Tux-It (C++)

1. Lancez l'application Tux-It pour la première fois afin d'ouvrir l'assistant graphique.
2. Cochez **"Activer la synchronisation en ligne"**.
3. Saisissez l'URL de votre serveur (ex : `http://localhost:8282`) et l'une des clés d'API générées sur votre console `/admin`.
4. Vos notes seront synchronisées automatiquement et sécurisées à chaque changement ! 🐧
