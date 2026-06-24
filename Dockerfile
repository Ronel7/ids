# ── Image de base légère Python ──
FROM python:3.11-slim

# Métadonnées
LABEL maintainer="IDS APP"
LABEL description="Système de Détection d'Intrusions — Random Forest NSL-KDD"

# Répertoire de travail
WORKDIR /app

# Copier les dépendances en premier (cache Docker optimisé)
COPY requirements.txt .
RUN pip install --no-cache-dir -r requirements.txt

# Copier le reste du projet
COPY . .

# Port exposé (Railway injecte $PORT automatiquement)
EXPOSE 5000

# Démarrage de l'API
CMD ["sh", "-c", "gunicorn --bind 0.0.0.0:${PORT:-7860} --timeout 120 app:app"]
