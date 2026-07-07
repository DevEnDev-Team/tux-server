# Étape 1 : Compilation du binaire Go
FROM golang:1.25-alpine AS builder

WORKDIR /app

# Copier les fichiers de dépendances Go
COPY go.mod go.sum ./

# Télécharger les dépendances
RUN go mod download

# Copier le code source
COPY main.go .

# Compiler de manière statique et optimisée (sans symboles de débogage)
RUN CGO_ENABLED=0 GOOS=linux go build -ldflags="-w -s" -o tux-server main.go

# Étape 2 : Image d'exécution minimale
FROM alpine:latest

WORKDIR /app

# Copier uniquement le binaire compilé depuis l'étape de build
COPY --from=builder /app/tux-server .

# Créer le répertoire pour les volumes de données
RUN mkdir data

# Port exposé
EXPOSE 8282

# Exécuter le serveur
CMD ["./tux-server"]
