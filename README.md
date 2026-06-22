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
# 1. Créer un environnement virtuel 
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


## Modèle
```
- Algorithme : Random Forest
- Dataset d'entraînement : NSL-KDD
- Features : 41 (extraites automatiquement depuis le `.pcap` par `app.py`)

```
