"""
═══════════════════════════════════════════════════════════════
  IDS API — Système de Détection d'Intrusions
  Stack : FastAPI + Random Forest (NSL-KDD)
  Deploy: Railway
═══════════════════════════════════════════════════════════════
"""

import os
import joblib
import numpy as np
import pandas as pd
from fastapi import FastAPI, HTTPException
from fastapi.middleware.cors import CORSMiddleware
from pydantic import BaseModel, Field
from typing import Optional
import uvicorn

# ─────────────────────────────────────────────────────────────
# Chargement du modèle au démarrage
# ─────────────────────────────────────────────────────────────
BASE_DIR   = os.path.dirname(os.path.abspath(__file__))
MODEL_PATH = os.path.join(BASE_DIR, "model.pkl")

bundle   = joblib.load(MODEL_PATH)
model    = bundle["model"]
scaler   = bundle["scaler"]
encoders = bundle["encoders"]
FEATURES = bundle["features"]

# ─────────────────────────────────────────────────────────────
# Application FastAPI
# ─────────────────────────────────────────────────────────────
app = FastAPI(
    title="IDS API — Détection d'Intrusions",
    description=(
        "API de détection d'intrusions réseau basée sur un modèle "
        "Random Forest entraîné sur le dataset NSL-KDD. "
        "Envoie les features d'une connexion réseau et reçois "
        "une prédiction normal/anomalie avec score de confiance."
    ),
    version="1.0.0",
)

app.add_middleware(
    CORSMiddleware,
    allow_origins=["*"],
    allow_methods=["*"],
    allow_headers=["*"],
)

# ─────────────────────────────────────────────────────────────
# Schéma d'entrée (les 41 features NSL-KDD)
# ─────────────────────────────────────────────────────────────
class ConnectionFeatures(BaseModel):
    # Features temporelles
    duration:              float = Field(0,    description="Durée de la connexion (secondes)")
    protocol_type:         str   = Field("tcp",description="Protocole : tcp, udp, icmp")
    service:               str   = Field("http",description="Service réseau : http, ftp, ssh, ...")
    flag:                  str   = Field("SF",  description="Statut de la connexion : SF, REJ, S0, ...")
    src_bytes:             float = Field(0,    description="Octets envoyés par la source")
    dst_bytes:             float = Field(0,    description="Octets envoyés par la destination")
    land:                  float = Field(0)
    wrong_fragment:        float = Field(0)
    urgent:                float = Field(0)
    # Features de contenu
    hot:                   float = Field(0)
    num_failed_logins:     float = Field(0)
    logged_in:             float = Field(0)
    num_compromised:       float = Field(0)
    root_shell:            float = Field(0)
    su_attempted:          float = Field(0)
    num_root:              float = Field(0)
    num_file_creations:    float = Field(0)
    num_shells:            float = Field(0)
    num_access_files:      float = Field(0)
    num_outbound_cmds:     float = Field(0)
    is_host_login:         float = Field(0)
    is_guest_login:        float = Field(0)
    # Features de trafic (fenêtre 2 secondes)
    count:                 float = Field(1)
    srv_count:             float = Field(1)
    serror_rate:           float = Field(0.0)
    srv_serror_rate:       float = Field(0.0)
    rerror_rate:           float = Field(0.0)
    srv_rerror_rate:       float = Field(0.0)
    same_srv_rate:         float = Field(1.0)
    diff_srv_rate:         float = Field(0.0)
    srv_diff_host_rate:    float = Field(0.0)
    # Features de trafic (fenêtre 100 connexions)
    dst_host_count:             float = Field(1)
    dst_host_srv_count:         float = Field(1)
    dst_host_same_srv_rate:     float = Field(1.0)
    dst_host_diff_srv_rate:     float = Field(0.0)
    dst_host_same_src_port_rate:float = Field(1.0)
    dst_host_srv_diff_host_rate:float = Field(0.0)
    dst_host_serror_rate:       float = Field(0.0)
    dst_host_srv_serror_rate:   float = Field(0.0)
    dst_host_rerror_rate:       float = Field(0.0)
    dst_host_srv_rerror_rate:   float = Field(0.0)

    class Config:
        json_schema_extra = {
            "example": {
                "duration": 0,
                "protocol_type": "tcp",
                "service": "http",
                "flag": "SF",
                "src_bytes": 232,
                "dst_bytes": 8153,
                "land": 0,
                "wrong_fragment": 0,
                "urgent": 0,
                "hot": 0,
                "num_failed_logins": 0,
                "logged_in": 1,
                "num_compromised": 0,
                "root_shell": 0,
                "su_attempted": 0,
                "num_root": 0,
                "num_file_creations": 0,
                "num_shells": 0,
                "num_access_files": 0,
                "num_outbound_cmds": 0,
                "is_host_login": 0,
                "is_guest_login": 0,
                "count": 8,
                "srv_count": 8,
                "serror_rate": 0.0,
                "srv_serror_rate": 0.0,
                "rerror_rate": 0.0,
                "srv_rerror_rate": 0.0,
                "same_srv_rate": 1.0,
                "diff_srv_rate": 0.0,
                "srv_diff_host_rate": 0.0,
                "dst_host_count": 9,
                "dst_host_srv_count": 9,
                "dst_host_same_srv_rate": 1.0,
                "dst_host_diff_srv_rate": 0.0,
                "dst_host_same_src_port_rate": 0.11,
                "dst_host_srv_diff_host_rate": 0.0,
                "dst_host_serror_rate": 0.0,
                "dst_host_srv_serror_rate": 0.0,
                "dst_host_rerror_rate": 0.0,
                "dst_host_srv_rerror_rate": 0.0,
            }
        }

# ─────────────────────────────────────────────────────────────
# Schéma de sortie
# ─────────────────────────────────────────────────────────────
class PredictionResult(BaseModel):
    prediction:   str   # "NORMALE" ou "ANOMALIE"
    label:        int   # 0 ou 1
    confidence:   float # probabilité 0.0 → 1.0
    alert_level:  str   # "OK", "MEDIUM", "HIGH", "CRITICAL"
    top_features: dict  # les 5 features les plus importantes de cette connexion

# ─────────────────────────────────────────────────────────────
# Utilitaire : encoder une connexion
# ─────────────────────────────────────────────────────────────
def encode_connection(conn: ConnectionFeatures) -> pd.DataFrame:
    data = conn.model_dump()

    # Encodage des variables catégorielles
    for col, le in encoders.items():
        val = data[col]
        if val not in le.classes_:
            # Valeur inconnue → classe la plus fréquente (index 0)
            data[col] = 0
        else:
            data[col] = int(le.transform([val])[0])

    row = pd.DataFrame([data])[FEATURES]
    return row

def alert_level(label: int, confidence: float) -> str:
    if label == 0:
        return "OK"
    if confidence >= 0.95:
        return "CRITICAL"
    if confidence >= 0.80:
        return "HIGH"
    return "MEDIUM"

# ─────────────────────────────────────────────────────────────
# ROUTES
# ─────────────────────────────────────────────────────────────

@app.get("/", tags=["Statut"])
def root():
    return {
        "service": "IDS API — Détection d'Intrusions",
        "version": "1.0.0",
        "status":  "running",
        "endpoints": {
            "predict":    "POST /predict",
            "batch":      "POST /predict/batch",
            "health":     "GET  /health",
            "docs":       "GET  /docs",
        }
    }

@app.get("/health", tags=["Statut"])
def health():
    """Vérifie que l'API et le modèle sont opérationnels."""
    return {
        "status":          "healthy",
        "model":           "RandomForestClassifier",
        "features_count":  len(FEATURES),
        "model_estimators": model.n_estimators,
    }

@app.post("/predict", response_model=PredictionResult, tags=["Détection"])
def predict(conn: ConnectionFeatures):
    """
    Analyse une connexion réseau et retourne :
    - prediction : NORMALE ou ANOMALIE
    - confidence : score de confiance (0 → 1)
    - alert_level : OK / MEDIUM / HIGH / CRITICAL
    - top_features : les 5 features les plus déterminantes
    """
    try:
        row    = encode_connection(conn)
        row_sc = scaler.transform(row)

        label     = int(model.predict(row_sc)[0])
        proba     = float(model.predict_proba(row_sc)[0][label])
        prediction= "ANOMALIE 🚨" if label == 1 else "NORMALE ✅"
        level     = alert_level(label, proba)

        # Top 5 features les plus importantes pour cette prédiction
        importances = model.feature_importances_
        top_idx     = np.argsort(importances)[::-1][:5]
        top_feats   = {
            FEATURES[i]: round(float(row.iloc[0, i]), 4)
            for i in top_idx
        }

        return PredictionResult(
            prediction=prediction,
            label=label,
            confidence=round(proba, 4),
            alert_level=level,
            top_features=top_feats,
        )

    except Exception as e:
        raise HTTPException(status_code=500, detail=str(e))

@app.post("/predict/batch", tags=["Détection"])
def predict_batch(connections: list[ConnectionFeatures]):
    """
    Analyse plusieurs connexions en une seule requête.
    Retourne la liste des résultats + un résumé.
    """
    if len(connections) > 1000:
        raise HTTPException(
            status_code=400,
            detail="Maximum 1000 connexions par batch."
        )

    results   = []
    anomalies = 0

    for conn in connections:
        row    = encode_connection(conn)
        row_sc = scaler.transform(row)
        label  = int(model.predict(row_sc)[0])
        proba  = float(model.predict_proba(row_sc)[0][label])
        level  = alert_level(label, proba)

        if label == 1:
            anomalies += 1

        results.append({
            "prediction":  "ANOMALIE" if label == 1 else "NORMALE",
            "label":       label,
            "confidence":  round(proba, 4),
            "alert_level": level,
        })

    return {
        "total":        len(connections),
        "anomalies":    anomalies,
        "normal":       len(connections) - anomalies,
        "anomaly_rate": round(anomalies / len(connections) * 100, 2),
        "results":      results,
    }

# ─────────────────────────────────────────────────────────────
# Lancement local
# ─────────────────────────────────────────────────────────────
if __name__ == "__main__":
    port = int(os.environ.get("PORT", 8000))
    uvicorn.run("main:app", host="0.0.0.0", port=port, reload=False)
