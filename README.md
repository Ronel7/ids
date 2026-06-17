# IDS App — Système de Détection d'Intrusions

Application web Flask qui analyse un fichier `.pcap`, extrait les 41 features NSL-KDD,
et applique un modèle Random Forest pour détecter les connexions anormales.

## Contenu du projet

```
ids_app/
├── app.py              # Application Flask principale (point d'entrée)
├── extractor.py         # Script autonome d'extraction de features (non utilisé par app.py)
├── model.pkl            # Modèle Random Forest + scaler + encodeurs
├── templates/
│   └── index.html       # Interface web (upload + résultats)
├── requirements.txt     # Dépendances Python
├── Dockerfile            # Image Docker pour le déploiement
├── .dockerignore         # Fichiers exclus de l'image Docker
├── railway.toml          # Configuration Railway
├── .gitignore             # Fichiers exclus de Git
└── README.md
```

---

## Lancer en local

```bash
# 1. Créer un environnement virtuel (recommandé)
python -m venv venv
venv\Scripts\activate          # Windows
source venv/bin/activate       # Mac/Linux

# 2. Installer les dépendances
pip install -r requirements.txt

# 3. Lancer l'application
python app.py

# 4. Ouvrir dans le navigateur
http://localhost:5000
```

---

## Déploiement sur GitHub

### Étape 1 — Initialiser le dépôt Git

Dans le dossier du projet (celui qui contient `app.py`, pas le dossier `venv`) :

```bash
git init
git add .
git commit -m "Initial commit — IDS App"
```

> Le fichier `.gitignore` empêche le dossier `venv/` et les fichiers `.pcap`/`.arff`
> d'être envoyés sur GitHub — c'est normal et voulu, ces fichiers sont trop volumineux
> et inutiles pour le déploiement.

### Étape 2 — Créer le dépôt sur GitHub

1. Va sur [github.com/new](https://github.com/new)
2. Donne un nom au dépôt (ex: `ids-detection-app`)
3. Ne coche **aucune** case (pas de README, pas de .gitignore — tu les as déjà)
4. Clique **Create repository**

### Étape 3 — Pousser le code

GitHub te donne des commandes après création, généralement :

```bash
git remote add origin https://github.com/TON_USERNAME/ids-detection-app.git
git branch -M main
git push -u origin main
```

---


## Modèle

- **Algorithme** : Random Forest
- **Dataset d'entraînement** : NSL-KDD
- **Features** : 41 (extraites automatiquement depuis le `.pcap` par `app.py`)
