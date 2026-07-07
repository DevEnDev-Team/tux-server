package main

import (
	"database/sql"
	"encoding/json"
	"io"
	"log"
	"net/http"
	"os"
	"path/filepath"
	"strings"

	_ "github.com/glebarez/go-sqlite"
	"golang.org/x/crypto/bcrypt"
)

const (
	defaultPort = "8282"
	dataDir     = "data"
)

var (
	db                *sql.DB
	adminPasswordHash string
)

func init() {
	// Créer le répertoire de stockage
	if err := os.MkdirAll(dataDir, 0755); err != nil {
		log.Fatalf("Impossible de créer le répertoire de données : %v", err)
	}

	// Initialiser SQLite
	dbPath := filepath.Join(dataDir, "postit.db")
	var err error
	db, err = sql.Open("sqlite", dbPath)
	if err != nil {
		log.Fatalf("Impossible d'ouvrir la base SQLite : %v", err)
	}

	// Activer les clés étrangères pour la suppression en cascade
	if _, err := db.Exec("PRAGMA foreign_keys = ON;"); err != nil {
		log.Fatalf("Impossible d'activer les clés étrangères (PRAGMA foreign_keys) : %v", err)
	}

	// Créer les tables
	createTables()

	// Charger le mot de passe d'administration
	loadAdminPassword()
}

func loadAdminPassword() {
	// Créer la table settings si elle n'existe pas
	_, err := db.Exec(`
	CREATE TABLE IF NOT EXISTS settings (
		key TEXT PRIMARY KEY,
		value TEXT
	);`)
	if err != nil {
		log.Fatalf("Erreur table settings : %v", err)
	}

	envPassword := os.Getenv("ADMIN_PASSWORD")

	var dbPasswordHash string
	err = db.QueryRow("SELECT value FROM settings WHERE key = 'admin_password'").Scan(&dbPasswordHash)

	if envPassword != "" {
		// La variable d'environnement a la priorité.
		// Pour éviter de re-hasher à chaque démarrage si c'est identique, on vérifie s'il correspond au hash actuel.
		var needsUpdate bool
		if err == nil && dbPasswordHash != "" {
			errCompare := bcrypt.CompareHashAndPassword([]byte(dbPasswordHash), []byte(envPassword))
			if errCompare != nil {
				needsUpdate = true
			} else {
				adminPasswordHash = dbPasswordHash
			}
		} else {
			needsUpdate = true
		}

		if needsUpdate {
			newHash, errHash := bcrypt.GenerateFromPassword([]byte(envPassword), bcrypt.DefaultCost)
			if errHash != nil {
				log.Fatalf("Erreur hachage du mot de passe environnement : %v", errHash)
			}
			adminPasswordHash = string(newHash)
			_, _ = db.Exec("INSERT INTO settings (key, value) VALUES ('admin_password', ?) ON CONFLICT(key) DO UPDATE SET value = excluded.value", adminPasswordHash)
		}
	} else if err == nil && dbPasswordHash != "" {
		// Sinon on prend la valeur (qui est un hash) en base de données
		adminPasswordHash = dbPasswordHash
	} else {
		// Sinon valeur par défaut "admin" hachée
		defaultPassword := "admin"
		newHash, errHash := bcrypt.GenerateFromPassword([]byte(defaultPassword), bcrypt.DefaultCost)
		if errHash != nil {
			log.Fatalf("Erreur hachage du mot de passe par défaut : %v", errHash)
		}
		adminPasswordHash = string(newHash)
		_, _ = db.Exec("INSERT INTO settings (key, value) VALUES ('admin_password', ?) ON CONFLICT(key) DO UPDATE SET value = excluded.value", adminPasswordHash)
	}
}

func createTables() {
	// Table des clés d'API autorisées
	queryKeys := `
	CREATE TABLE IF NOT EXISTS api_keys (
		key_value TEXT PRIMARY KEY,
		description TEXT,
		created_at DATETIME DEFAULT CURRENT_TIMESTAMP
	);`
	if _, err := db.Exec(queryKeys); err != nil {
		log.Fatalf("Erreur table api_keys : %v", err)
	}

	// Table des notes par clé d'API
	queryNotes := `
	CREATE TABLE IF NOT EXISTS sync_data (
		api_key TEXT PRIMARY KEY,
		notes_json TEXT,
		updated_at DATETIME DEFAULT CURRENT_TIMESTAMP,
		FOREIGN KEY(api_key) REFERENCES api_keys(key_value) ON DELETE CASCADE
	);`
	if _, err := db.Exec(queryNotes); err != nil {
		log.Fatalf("Erreur table sync_data : %v", err)
	}

	// Insérer une clé d'API par défaut si la table est vide
	var count int
	err := db.QueryRow("SELECT COUNT(*) FROM api_keys").Scan(&count)
	if err == nil && count == 0 {
		_, _ = db.Exec("INSERT INTO api_keys (key_value, description) VALUES (?, ?)", "default_mango_key", "Clé créée automatiquement au démarrage")
	}
}

// Middleware d'authentification Bearer Token pour le client Post-It
func authenticateClient(next http.HandlerFunc) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Access-Control-Allow-Origin", "*")
		w.Header().Set("Access-Control-Allow-Methods", "GET, POST, OPTIONS")
		w.Header().Set("Access-Control-Allow-Headers", "Content-Type, Authorization")

		if r.Method == "OPTIONS" {
			w.WriteHeader(http.StatusOK)
			return
		}

		authHeader := r.Header.Get("Authorization")
		if authHeader == "" {
			http.Error(w, `{"error": "En-tête Authorization manquant"}`, http.StatusUnauthorized)
			return
		}

		parts := strings.Split(authHeader, " ")
		if len(parts) != 2 || strings.ToLower(parts[0]) != "bearer" {
			http.Error(w, `{"error": "Format d'authentification invalide"}`, http.StatusUnauthorized)
			return
		}

		apiKey := strings.TrimSpace(parts[1])
		if apiKey == "" {
			http.Error(w, `{"error": "Clé d'API vide"}`, http.StatusUnauthorized)
			return
		}

		// Valider la clé d'API par rapport à la base SQLite
		var exists bool
		err := db.QueryRow("SELECT EXISTS(SELECT 1 FROM api_keys WHERE key_value = ?)", apiKey).Scan(&exists)
		if err != nil || !exists {
			http.Error(w, `{"error": "Clé d'API invalide ou non autorisée"}`, http.StatusUnauthorized)
			return
		}

		r.Header.Set("X-Validated-API-Key", apiKey)
		next(w, r)
	}
}

// Middleware d'authentification pour le panneau d'administration
func authenticateAdmin(next http.HandlerFunc) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Access-Control-Allow-Origin", "*")
		w.Header().Set("Access-Control-Allow-Methods", "GET, POST, DELETE, OPTIONS")
		w.Header().Set("Access-Control-Allow-Headers", "Content-Type, Authorization")

		if r.Method == "OPTIONS" {
			w.WriteHeader(http.StatusOK)
			return
		}

		authHeader := r.Header.Get("Authorization")
		if authHeader == "" {
			http.Error(w, `{"error": "Authentification admin requise"}`, http.StatusUnauthorized)
			return
		}

		parts := strings.Split(authHeader, " ")
		if len(parts) != 2 || strings.ToLower(parts[0]) != "bearer" {
			http.Error(w, `{"error": "Format d'authentification invalide"}`, http.StatusUnauthorized)
			return
		}

		errCompare := bcrypt.CompareHashAndPassword([]byte(adminPasswordHash), []byte(parts[1]))
		if errCompare != nil {
			http.Error(w, `{"error": "Mot de passe administration incorrect"}`, http.StatusUnauthorized)
			return
		}

		next(w, r)
	}
}

// Handler de synchronisation des notes du client
func handleNotes(w http.ResponseWriter, r *http.Request) {
	apiKey := r.Header.Get("X-Validated-API-Key")

	switch r.Method {
	case "GET":
		var notesJSON string
		query := "SELECT notes_json FROM sync_data WHERE api_key = ?"
		err := db.QueryRow(query, apiKey).Scan(&notesJSON)
		
		if err == sql.ErrNoRows {
			w.Header().Set("Content-Type", "application/json")
			w.Write([]byte("[]"))
			return
		} else if err != nil {
			http.Error(w, `{"error": "Erreur de base de données"}`, http.StatusInternalServerError)
			return
		}

		w.Header().Set("Content-Type", "application/json")
		w.Write([]byte(notesJSON))

	case "POST":
		body, err := io.ReadAll(r.Body)
		if err != nil {
			http.Error(w, `{"error": "Erreur lors de la lecture de la requête"}`, http.StatusBadRequest)
			return
		}

		var jsonTest []interface{}
		if err := json.Unmarshal(body, &jsonTest); err != nil {
			http.Error(w, `{"error": "Format JSON invalide"}`, http.StatusBadRequest)
			return
		}

		query := `
		INSERT INTO sync_data (api_key, notes_json, updated_at)
		VALUES (?, ?, CURRENT_TIMESTAMP)
		ON CONFLICT(api_key) DO UPDATE SET
			notes_json = excluded.notes_json,
			updated_at = CURRENT_TIMESTAMP;`
		
		if _, err := db.Exec(query, apiKey, string(body)); err != nil {
			http.Error(w, `{"error": "Erreur d'écriture en base de données"}`, http.StatusInternalServerError)
			return
		}

		w.Header().Set("Content-Type", "application/json")
		w.Write([]byte(`{"status": "success", "message": "Notes synchronisées dans SQLite"}`))

	default:
		http.Error(w, `{"error": "Méthode non autorisée"}`, http.StatusMethodNotAllowed)
	}
}

// --- API d'Administration pour les Clés ---
type ApiKeyInfo struct {
	KeyValue    string `json:"key_value"`
	Description string `json:"description"`
	CreatedAt   string `json:"created_at"`
}

func handleAdminKeys(w http.ResponseWriter, r *http.Request) {
	switch r.Method {
	case "GET":
		rows, err := db.Query("SELECT key_value, description, created_at FROM api_keys ORDER BY created_at DESC")
		if err != nil {
			http.Error(w, `{"error": "Erreur de lecture"}`, http.StatusInternalServerError)
			return
		}
		defer rows.Close()

		var list []ApiKeyInfo
		for rows.Next() {
			var info ApiKeyInfo
			if err := rows.Scan(&info.KeyValue, &info.Description, &info.CreatedAt); err == nil {
				list = append(list, info)
			}
		}

		w.Header().Set("Content-Type", "application/json")
		json.NewEncoder(w).Encode(list)

	case "POST":
		var info ApiKeyInfo
		if err := json.NewDecoder(r.Body).Decode(&info); err != nil {
			http.Error(w, `{"error": "JSON invalide"}`, http.StatusBadRequest)
			return
		}

		info.KeyValue = strings.TrimSpace(info.KeyValue)
		if info.KeyValue == "" {
			http.Error(w, `{"error": "La clé d'API ne peut pas être vide"}`, http.StatusBadRequest)
			return
		}

		_, err := db.Exec("INSERT INTO api_keys (key_value, description) VALUES (?, ?)", info.KeyValue, info.Description)
		if err != nil {
			http.Error(w, `{"error": "Cette clé d'API existe déjà"}`, http.StatusConflict)
			return
		}

		w.Header().Set("Content-Type", "application/json")
		w.Write([]byte(`{"status": "success", "message": "Clé d'API ajoutée avec succès"}`))

	default:
		http.Error(w, `{"error": "Méthode non autorisée"}`, http.StatusMethodNotAllowed)
	}
}

func handleAdminDeleteKey(w http.ResponseWriter, r *http.Request) {
	if r.Method != "DELETE" {
		http.Error(w, `{"error": "Méthode non autorisée"}`, http.StatusMethodNotAllowed)
		return
	}

	// Extraire la clé depuis l'URL /admin/api/keys/delete?key=xxxx
	keyToDelete := r.URL.Query().Get("key")
	if keyToDelete == "" {
		http.Error(w, `{"error": "Paramètre key manquant"}`, http.StatusBadRequest)
		return
	}

	// La suppression en cascade effacera automatiquement les notes associées dans sync_data
	_, err := db.Exec("DELETE FROM api_keys WHERE key_value = ?", keyToDelete)
	if err != nil {
		http.Error(w, `{"error": "Erreur lors de la suppression de la clé"}`, http.StatusInternalServerError)
		return
	}

	w.Header().Set("Content-Type", "application/json")
	w.Write([]byte(`{"status": "success", "message": "Clé et notes associées supprimées"}`))
}

type ChangePasswordRequest struct {
	NewPassword string `json:"new_password"`
}

func handleAdminChangePassword(w http.ResponseWriter, r *http.Request) {
	if r.Method != "POST" {
		http.Error(w, `{"error": "Méthode non autorisée"}`, http.StatusMethodNotAllowed)
		return
	}

	var req ChangePasswordRequest
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
		http.Error(w, `{"error": "JSON invalide"}`, http.StatusBadRequest)
		return
	}

	req.NewPassword = strings.TrimSpace(req.NewPassword)
	if req.NewPassword == "" {
		http.Error(w, `{"error": "Le mot de passe ne peut pas être vide"}`, http.StatusBadRequest)
		return
	}

	// Générer le hash bcrypt
	newHash, err := bcrypt.GenerateFromPassword([]byte(req.NewPassword), bcrypt.DefaultCost)
	if err != nil {
		http.Error(w, `{"error": "Erreur lors de la sécurisation du mot de passe"}`, http.StatusInternalServerError)
		return
	}

	// Mettre à jour en base de données
	_, err = db.Exec("INSERT INTO settings (key, value) VALUES ('admin_password', ?) ON CONFLICT(key) DO UPDATE SET value = excluded.value", string(newHash))
	if err != nil {
		http.Error(w, `{"error": "Erreur lors de la mise à jour du mot de passe"}`, http.StatusInternalServerError)
		return
	}

	// Mettre à jour la variable globale en mémoire
	adminPasswordHash = string(newHash)

	w.Header().Set("Content-Type", "application/json")
	w.Write([]byte(`{"status": "success", "message": "Mot de passe administrateur mis à jour avec succès"}`))
}

// Sert la page Web d'administration (UI embarquée ultra-premium)
func handleAdminPanel(w http.ResponseWriter, r *http.Request) {
	w.Header().Set("Content-Type", "text/html; charset=utf-8")
	w.Write([]byte(adminHTML))
}

func main() {
	defer db.Close()

	port := os.Getenv("PORT")
	if port == "" {
		port = defaultPort
	}

	// Routes clients
	http.HandleFunc("/notes", authenticateClient(handleNotes))

	// Routes administrations
	http.HandleFunc("/admin", handleAdminPanel)
	http.HandleFunc("/admin/api/keys", authenticateAdmin(handleAdminKeys))
	http.HandleFunc("/admin/api/keys/delete", authenticateAdmin(handleAdminDeleteKey))
	http.HandleFunc("/admin/api/change-password", authenticateAdmin(handleAdminChangePassword))

	// Route racine : Sert la PWA mobile (fichiers statiques) si le dossier existe
	if _, err := os.Stat("./tux-mobile"); err == nil {
		log.Println("PWA mobile détectée dans ./tux-mobile. Liaison à la racine /")
		fs := http.FileServer(http.Dir("./tux-mobile"))
		http.Handle("/", fs)
	} else if _, err := os.Stat("./web"); err == nil {
		log.Println("PWA mobile détectée dans ./web. Liaison à la racine /")
		fs := http.FileServer(http.Dir("./web"))
		http.Handle("/", fs)
	}

	log.Printf("=== Serveur de Synchronisation Post-It (SQLite) ===")
	log.Printf("Port d'écoute : %s", port)
	log.Printf("Panneau d'administration disponible sur : http://localhost:%s/admin", port)
	
	// Vérifier si le mot de passe par défaut est toujours actif
	errCompare := bcrypt.CompareHashAndPassword([]byte(adminPasswordHash), []byte("admin"))
	if errCompare == nil {
		log.Println("ATTENTION : Le mot de passe d'administration par défaut est 'admin'. Veuillez définir la variable d'environnement ADMIN_PASSWORD pour le sécuriser.")
	}

	if err := http.ListenAndServe(":"+port, nil); err != nil {
		log.Fatalf("Erreur serveur : %v", err)
	}
}

// Page Web d'administration (HTML / CSS Vanilla moderne style Glassmorphism violet/indigo)
const adminHTML = `
<!DOCTYPE html>
<html lang="fr">
<head>
    <meta charset="UTF-8">
    <meta name="viewport" content="width=device-width, initial-scale=1.0">
    <title>Post-It - Administration</title>
    <link href="https://fonts.googleapis.com/css2?family=Outfit:wght@300;400;600;800&display=swap" rel="stylesheet">
    <style>
        :root {
            --bg-color: #0b0f19;
            --card-bg: rgba(255, 255, 255, 0.03);
            --border-color: rgba(255, 255, 255, 0.08);
            --primary: #6366f1;
            --primary-hover: #4f46e5;
            --danger: #ef4444;
            --danger-hover: #dc2626;
            --text: #f3f4f6;
            --text-muted: #9ca3af;
        }

        * {
            box-sizing: border-box;
            margin: 0;
            padding: 0;
            font-family: 'Outfit', sans-serif;
        }

        body {
            background-color: var(--bg-color);
            color: var(--text);
            min-height: 100vh;
            display: flex;
            justify-content: center;
            align-items: center;
            padding: 20px;
            background-image: 
                radial-gradient(at 0% 0%, rgba(99, 102, 241, 0.15) 0px, transparent 50%),
                radial-gradient(at 100% 100%, rgba(239, 68, 68, 0.08) 0px, transparent 50%);
        }

        .container {
            width: 100%;
            max-width: 800px;
            background: var(--card-bg);
            backdrop-filter: blur(16px);
            -webkit-backdrop-filter: blur(16px);
            border: 1px solid var(--border-color);
            border-radius: 20px;
            padding: 40px;
            box-shadow: 0 20px 40px rgba(0, 0, 0, 0.3);
        }

        h1 {
            font-size: 28px;
            font-weight: 800;
            margin-bottom: 8px;
            background: linear-gradient(to right, #ffffff, #9ca3af);
            -webkit-background-clip: text;
            -webkit-text-fill-color: transparent;
        }

        .subtitle {
            color: var(--text-muted);
            font-size: 14px;
            margin-bottom: 30px;
        }

        /* --- Écran Connexion --- */
        #login-view {
            text-align: center;
            max-width: 400px;
            margin: 0 auto;
        }

        .form-group {
            margin-bottom: 20px;
            text-align: left;
        }

        label {
            display: block;
            font-size: 13px;
            font-weight: 600;
            margin-bottom: 6px;
            color: var(--text-muted);
        }

        input {
            width: 100%;
            background: rgba(255, 255, 255, 0.05);
            border: 1px solid var(--border-color);
            border-radius: 8px;
            padding: 12px 16px;
            color: white;
            font-size: 14px;
            transition: all 0.3s ease;
        }

        input:focus {
            outline: none;
            border-color: var(--primary);
            box-shadow: 0 0 0 2px rgba(99, 102, 241, 0.2);
        }

        button {
            width: 100%;
            background: var(--primary);
            color: white;
            border: none;
            border-radius: 8px;
            padding: 12px;
            font-size: 14px;
            font-weight: 600;
            cursor: pointer;
            transition: background 0.2s ease;
        }

        button:hover {
            background: var(--primary-hover);
        }

        /* --- Écran Dashboard --- */
        #dashboard-view {
            display: none;
        }

        .header-actions {
            display: flex;
            justify-content: space-between;
            align-items: center;
            margin-bottom: 24px;
        }

        .logout-btn {
            background: transparent;
            border: 1px solid var(--border-color);
            color: var(--text-muted);
            width: auto;
            padding: 8px 16px;
        }

        .logout-btn:hover {
            background: rgba(255, 255, 255, 0.05);
            color: white;
        }

        .card {
            background: rgba(255, 255, 255, 0.02);
            border: 1px solid var(--border-color);
            border-radius: 12px;
            padding: 24px;
            margin-bottom: 30px;
        }

        .card h2 {
            font-size: 18px;
            font-weight: 600;
            margin-bottom: 16px;
        }

        .row-inputs {
            display: flex;
            gap: 16px;
        }

        .row-inputs .form-group {
            flex: 1;
            margin-bottom: 0;
        }

        .row-inputs button {
            width: auto;
            align-self: flex-end;
            padding: 12px 24px;
        }

        table {
            width: 100%;
            border-collapse: collapse;
            margin-top: 10px;
        }

        th {
            text-align: left;
            padding: 12px 16px;
            font-size: 12px;
            text-transform: uppercase;
            color: var(--text-muted);
            border-bottom: 1px solid var(--border-color);
        }

        td {
            padding: 16px;
            font-size: 14px;
            border-bottom: 1px solid var(--border-color);
        }

        tr:last-child td {
            border-bottom: none;
        }

        .btn-delete {
            background: rgba(239, 68, 68, 0.1);
            color: var(--danger);
            border: none;
            border-radius: 6px;
            padding: 6px 12px;
            font-size: 12px;
            cursor: pointer;
            width: auto;
            transition: all 0.2s ease;
        }

        .btn-delete:hover {
            background: var(--danger);
            color: white;
        }

        .badge-key {
            font-family: monospace;
            background: rgba(255, 255, 255, 0.08);
            padding: 4px 8px;
            border-radius: 4px;
            font-size: 13px;
        }

        #error-msg {
            color: var(--danger);
            font-size: 13px;
            margin-top: 12px;
            text-align: center;
            display: none;
        }
    </style>
</head>
<body>
    <div class="container">
        <!-- Vue Connexion -->
        <div id="login-view">
            <h1>Post-It Admin</h1>
            <p class="subtitle">Veuillez entrer le mot de passe d'administration</p>
            <div class="form-group">
                <label for="password">Mot de passe</label>
                <input type="password" id="password" placeholder="Mot de passe">
            </div>
            <button onclick="login()">Se connecter</button>
            <div id="error-msg"></div>
        </div>

        <!-- Vue Tableau de bord -->
        <div id="dashboard-view">
            <div class="header-actions">
                <div>
                    <h1>Console d'Administration</h1>
                    <p class="subtitle" style="margin-bottom: 0;">Gérez les clés d'API autorisées à synchroniser les Post-Its</p>
                </div>
                <button class="logout-btn" onclick="logout()">Déconnexion</button>
            </div>

            <!-- Formulaire ajout clé -->
            <div class="card">
                <h2>Créer une clé d'API</h2>
                <div class="row-inputs">
                    <div class="form-group">
                        <label for="new-key">Valeur de la clé</label>
                        <input type="text" id="new-key" placeholder="Ex: cle_secrete_de_mango">
                    </div>
                    <div class="form-group">
                        <label for="new-desc">Description / Propriétaire</label>
                        <input type="text" id="new-desc" placeholder="Ex: PC Portable Mango">
                    </div>
                    <button onclick="createKey()">Ajouter</button>
                </div>
            </div>

            <!-- Liste des clés existantes -->
            <div class="card" style="padding: 0; overflow: hidden;">
                <table>
                    <thead>
                        <tr>
                            <th>Clé d'API</th>
                            <th>Description</th>
                            <th>Date de création</th>
                            <th style="text-align: right;">Action</th>
                        </tr>
                    </thead>
                    <tbody id="keys-table-body">
                        <!-- Rempli par JS -->
                    </tbody>
                </table>
            </div>

            <!-- Formulaire changement mot de passe -->
            <div class="card">
                <h2>Modifier le mot de passe administrateur</h2>
                <div class="row-inputs">
                    <div class="form-group">
                        <label for="new-password">Nouveau mot de passe</label>
                        <input type="password" id="new-password" placeholder="Nouveau mot de passe">
                    </div>
                    <div class="form-group">
                        <label for="confirm-password">Confirmer le mot de passe</label>
                        <input type="password" id="confirm-password" placeholder="Confirmer le mot de passe">
                    </div>
                    <button onclick="changePassword()">Modifier</button>
                </div>
            </div>
        </div>
    </div>

    <script>
        let adminToken = localStorage.getItem("postit_admin_token") || "";

        if (adminToken) {
            showDashboard();
        }

        function showError(msg) {
            const el = document.getElementById("error-msg");
            el.innerText = msg;
            el.style.display = "block";
            setTimeout(() => { el.style.display = "none"; }, 4000);
        }

        function login() {
            const pass = document.getElementById("password").value;
            // On tente de faire une requête de test pour valider le token
            fetch("/admin/api/keys", {
                headers: { "Authorization": "Bearer " + pass }
            })
            .then(res => {
                if (res.ok) {
                    adminToken = pass;
                    localStorage.setItem("postit_admin_token", pass);
                    showDashboard();
                } else {
                    showError("Mot de passe incorrect ou refusé");
                }
            })
            .catch(() => showError("Erreur de communication avec le serveur"));
        }

        function logout() {
            adminToken = "";
            localStorage.removeItem("postit_admin_token");
            document.getElementById("dashboard-view").style.display = "none";
            document.getElementById("login-view").style.display = "block";
        }

        function showDashboard() {
            document.getElementById("login-view").style.display = "none";
            document.getElementById("dashboard-view").style.display = "block";
            loadKeys();
        }

        function loadKeys() {
            fetch("/admin/api/keys", {
                headers: { "Authorization": "Bearer " + adminToken }
            })
            .then(res => {
                if (res.status === 401) {
                    logout();
                    return;
                }
                return res.json();
            })
            .then(data => {
                if (!data) return;
                const tbody = document.getElementById("keys-table-body");
                tbody.innerHTML = "";
                data.forEach(item => {
                    const tr = document.createElement("tr");
                    tr.innerHTML = "<td><span class=\"badge-key\">" + item.key_value + "</span></td>" +
                        "<td>" + (item.description || "<span style=\"color:#777\">Aucune</span>") + "</td>" +
                        "<td style=\"color: var(--text-muted); font-size:12px\">" + item.created_at + "</td>" +
                        "<td style=\"text-align: right;\">" +
                            "<button class=\"btn-delete\" onclick=\"deleteKey('" + item.key_value + "')\">Supprimer</button>" +
                        "</td>";
                    tbody.appendChild(tr);
                });
            })
            .catch(() => console.log("Erreur de chargement des clés"));
        }

        function createKey() {
            const val = document.getElementById("new-key").value.trim();
            const desc = document.getElementById("new-desc").value.trim();

            if (!val) {
                alert("Veuillez saisir une valeur de clé.");
                return;
            }

            fetch("/admin/api/keys", {
                method: "POST",
                headers: { 
                    "Authorization": "Bearer " + adminToken,
                    "Content-Type": "application/json"
                },
                body: JSON.stringify({ key_value: val, description: desc })
            })
            .then(res => {
                if (res.status === 409) {
                    alert("Cette clé d'API existe déjà !");
                } else if (res.ok) {
                    document.getElementById("new-key").value = "";
                    document.getElementById("new-desc").value = "";
                    loadKeys();
                } else {
                    alert("Erreur de création de la clé");
                }
            });
        }

        function deleteKey(key) {
            if (!confirm("Voulez-vous vraiment supprimer la clé \"" + key + "\" ?\nToutes les notes synchronisées associées à cette clé seront définitivement effacées.")) {
                return;
            }

            fetch("/admin/api/keys/delete?key=" + encodeURIComponent(key), {
                method: "DELETE",
                headers: { "Authorization": "Bearer " + adminToken }
            })
            .then(res => {
                if (res.ok) {
                    loadKeys();
                } else {
                    alert("Erreur lors de la suppression");
                }
            });
        }

        function changePassword() {
            const newPass = document.getElementById("new-password").value;
            const confirmPass = document.getElementById("confirm-password").value;

            if (!newPass) {
                alert("Veuillez saisir un mot de passe.");
                return;
            }

            if (newPass !== confirmPass) {
                alert("Les mots de passe ne correspondent pas.");
                return;
            }

            fetch("/admin/api/change-password", {
                method: "POST",
                headers: { 
                    "Authorization": "Bearer " + adminToken,
                    "Content-Type": "application/json"
                },
                body: JSON.stringify({ new_password: newPass })
            })
            .then(res => {
                if (res.ok) {
                    alert("Le mot de passe administrateur a été modifié avec succès. Veuillez vous reconnecter.");
                    logout();
                } else {
                    res.json().then(data => {
                        alert("Erreur : " + (data.error || "Impossible de changer le mot de passe"));
                    });
                }
            })
            .catch(() => alert("Erreur lors de la communication avec le serveur"));
        }
    </script>
</body>
</html>
`
