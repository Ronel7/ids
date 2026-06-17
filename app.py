"""
═══════════════════════════════════════════════════════════════
  IDS App — Application de détection d'intrusions
  Pour l'utilisateur lambda : upload pcap → prédiction immédiate
  Stack : Flask + joblib + scapy
═══════════════════════════════════════════════════════════════
"""

import os, re, json, time, threading
from io import StringIO
from collections import defaultdict
from flask import Flask, render_template, request, jsonify
import pandas as pd
import numpy as np
import joblib

# ─────────────────────────────────────────────────────────────
# Chargement du modèle
# ─────────────────────────────────────────────────────────────
BASE_DIR   = os.path.dirname(os.path.abspath(__file__))
MODEL_PATH = os.path.join(BASE_DIR, "model.pkl")
bundle     = joblib.load(MODEL_PATH)
model      = bundle["model"]
scaler     = bundle["scaler"]
encoders   = bundle["encoders"]
FEATURES   = bundle["features"]

app = Flask(__name__)
app.config['MAX_CONTENT_LENGTH'] = 50 * 1024 * 1024  # 50MB max

# ─────────────────────────────────────────────────────────────
# PORT → SERVICE (NSL-KDD)
# ─────────────────────────────────────────────────────────────
PORT_SERVICE = {
    20:'ftp_data',21:'ftp',22:'ssh',23:'telnet',25:'smtp',
    53:'domain',79:'finger',80:'http',110:'pop_3',111:'sunrpc',
    119:'nntp',123:'ntp_u',139:'netbios_ssn',143:'imap4',
    179:'bgp',389:'ldap',443:'http_443',512:'exec',513:'login',
    514:'shell',515:'printer',993:'imap4',995:'pop_3',
    3306:'other',5432:'other',8080:'http',8443:'http_443',
}
def port_to_service(port, proto='tcp'):
    if proto == 'icmp': return 'eco_i'
    return PORT_SERVICE.get(port, 'private' if port > 1023 else 'other')

def deduce_flag(flags_seq, has_data_fwd, has_data_bwd):
    f = set(flags_seq)
    has_syn = 'S' in f; has_sa = 'SA' in f
    has_fin = 'FA' in f or 'F' in f
    has_rst = 'R' in f or 'RA' in f
    if has_syn and not has_sa and not has_rst: return 'S0'
    if has_syn and has_sa and has_fin and not has_rst: return 'SF'
    if has_syn and has_rst and not has_sa: return 'REJ'
    if has_syn and has_sa and has_rst: return 'RSTO' if has_data_fwd else 'RSTR'
    if has_syn and has_sa and not has_fin: return 'S1'
    return 'OTH'

# ─────────────────────────────────────────────────────────────
# Extraction des features depuis pcap
# ─────────────────────────────────────────────────────────────
def extract_features_from_pcap(pcap_path):
    try:
        from scapy.all import rdpcap, IP, TCP, Raw
    except ImportError:
        return None, "Scapy non installé"

    pkts = rdpcap(pcap_path)
    connections = defaultdict(list)
    for pkt in pkts:
        if not (pkt.haslayer(IP) and pkt.haslayer(TCP)): continue
        ip = pkt[IP]; tcp = pkt[TCP]
        key = tuple(sorted([(ip.src, tcp.sport), (ip.dst, tcp.dport)]))
        connections[key].append(pkt)

    records = []
    for conn_key, conn_pkts in connections.items():
        conn_pkts.sort(key=lambda p: p.time)
        ip0 = conn_pkts[0][IP]; tcp0 = conn_pkts[0][TCP]
        src_ip, src_port, dst_ip, dst_port = None, None, None, None
        for p in conn_pkts:
            tcp = p[TCP]
            if (tcp.flags & 0x02) and not (tcp.flags & 0x10):
                src_ip, src_port = p[IP].src, tcp.sport
                dst_ip, dst_port = p[IP].dst, tcp.dport
                break
        if src_ip is None:
            src_ip, dst_ip = ip0.src, ip0.dst
            src_port, dst_port = tcp0.sport, tcp0.dport

        t_start  = conn_pkts[0].time
        duration = round(conn_pkts[-1].time - t_start, 6)
        service  = port_to_service(dst_port)

        src_bytes = dst_bytes = 0
        flags_seen = []; has_fwd = has_bwd = False
        full_payload = b""
        for p in conn_pkts:
            if not p.haslayer(TCP): continue
            payload_len = len(p[TCP].payload)
            if p[IP].src == src_ip: src_bytes += payload_len
            else: dst_bytes += payload_len
            f = p[TCP].flags
            fs = ("S" if f&2 else "")+("A" if f&16 else "")+("P" if f&8 else "")+("F" if f&1 else "")+("R" if f&4 else "")
            if fs: flags_seen.append(fs)
            if payload_len > 0:
                if p[IP].src == src_ip: has_fwd = True
                else: has_bwd = True
            if p.haslayer(Raw): full_payload += bytes(p[Raw].load)

        flag = deduce_flag(flags_seen, has_fwd, has_bwd)
        ps = full_payload.decode('utf-8', errors='ignore').lower()

        records.append({
            'duration': duration, 'protocol_type': 'tcp',
            'service': service, 'flag': flag,
            'src_bytes': src_bytes, 'dst_bytes': dst_bytes,
            'land': 1 if src_ip==dst_ip and src_port==dst_port else 0,
            'wrong_fragment': 0, 'urgent': 0,
            'hot': sum(1 for kw in ['/etc/passwd','/root','sudo'] if kw in ps),
            'num_failed_logins': ps.count('permission denied'),
            'logged_in': 1 if any(kw in ps for kw in ['cookie:','200 ok','welcome']) else 0,
            'num_compromised': 0, 'root_shell': 1 if 'root@' in ps else 0,
            'su_attempted': 0, 'num_root': ps.count('root'),
            'num_file_creations': 0, 'num_shells': 0,
            'num_access_files': 0, 'num_outbound_cmds': 0,
            'is_host_login': 0, 'is_guest_login': 0,
            '_src_ip': src_ip, '_dst_ip': dst_ip,
            '_dst_port': dst_port, '_t_start': t_start, '_flag': flag,
        })

    if not records:
        return None, "Aucune connexion TCP trouvée dans le fichier"

    df = pd.DataFrame(records).sort_values('_t_start').reset_index(drop=True)

    # Features trafic
    for i, row in df.iterrows():
        t_now = row['_t_start']; svc = row['service']
        dst_ip = row['_dst_ip']; dst_port = row['_dst_port']
        win2 = df[(df['_t_start'] >= t_now-2) & (df['_t_start'] <= t_now)]
        sd = win2[win2['_dst_ip']==dst_ip]; n2 = max(len(sd),1)
        df.at[i,'count'] = n2
        df.at[i,'srv_count'] = len(sd[sd['service']==svc])
        df.at[i,'serror_rate'] = round(sd['_flag'].apply(lambda x: 1 if x in ('S0','S1','S2','S3') else 0).sum()/n2,3)
        df.at[i,'rerror_rate'] = round(sd['_flag'].apply(lambda x: 1 if x in ('REJ','RSTR') else 0).sum()/n2,3)
        df.at[i,'same_srv_rate'] = round(len(sd[sd['service']==svc])/n2,3)
        df.at[i,'diff_srv_rate'] = round(len(sd[sd['service']!=svc])/n2,3)
        df.at[i,'srv_serror_rate'] = 0.0; df.at[i,'srv_rerror_rate'] = 0.0
        df.at[i,'srv_diff_host_rate'] = 0.0
        win100 = df.iloc[max(0,i-99):i+1]
        sh = win100[win100['_dst_ip']==dst_ip]; n100 = max(len(sh),1)
        df.at[i,'dst_host_count'] = n100
        df.at[i,'dst_host_srv_count'] = len(sh[sh['service']==svc])
        df.at[i,'dst_host_same_srv_rate'] = round(len(sh[sh['service']==svc])/n100,3)
        df.at[i,'dst_host_diff_srv_rate'] = round(len(sh[sh['service']!=svc])/n100,3)
        df.at[i,'dst_host_same_src_port_rate'] = round(len(sh[sh['_dst_port']==dst_port])/n100,3)
        df.at[i,'dst_host_srv_diff_host_rate'] = 0.0
        df.at[i,'dst_host_serror_rate'] = round(sh['_flag'].apply(lambda x: 1 if x in ('S0','S1') else 0).sum()/n100,3)
        df.at[i,'dst_host_rerror_rate'] = round(sh['_flag'].apply(lambda x: 1 if x in ('REJ','RSTR') else 0).sum()/n100,3)
        df.at[i,'dst_host_srv_serror_rate'] = 0.0
        df.at[i,'dst_host_srv_rerror_rate'] = 0.0

    return df, None

def predict_dataframe(df):
    """Applique le modèle sur le DataFrame de features."""
    results = []
    for i, row in df.iterrows():
        r = row.copy()
        for col, le in encoders.items():
            val = str(r.get(col, 'tcp'))
            r[col] = int(le.transform([val])[0]) if val in le.classes_ else 0
        X = pd.DataFrame([r])[FEATURES].fillna(0)
        X_sc = scaler.transform(X)
        label = int(model.predict(X_sc)[0])
        proba = float(model.predict_proba(X_sc)[0][label])
        results.append({
            'id'          : i + 1,
            'src_ip'      : row.get('_src_ip', '?'),
            'dst_ip'      : row.get('_dst_ip', '?'),
            'dst_port'    : int(row.get('_dst_port', 0)),
            'service'     : row.get('service', '?'),
            'flag'        : row.get('flag', '?'),
            'src_bytes'   : int(row.get('src_bytes', 0)),
            'dst_bytes'   : int(row.get('dst_bytes', 0)),
            'prediction'  : 'ANOMALIE' if label == 1 else 'NORMALE',
            'confidence'  : round(proba * 100, 1),
            'alert_level' : 'CRITICAL' if (label==1 and proba>=0.95)
                            else 'HIGH'   if (label==1 and proba>=0.80)
                            else 'MEDIUM' if label==1
                            else 'OK',
        })
    return results

# ─────────────────────────────────────────────────────────────
# ROUTES
# ─────────────────────────────────────────────────────────────
@app.route('/')
def index():
    return render_template('index.html')

@app.route('/analyze', methods=['POST'])
def analyze():
    if 'file' not in request.files:
        return jsonify({'error': 'Aucun fichier reçu'}), 400
    f = request.files['file']
    if not f.filename.endswith('.pcap'):
        return jsonify({'error': 'Fichier .pcap requis'}), 400

    # Sauvegarder temporairement
    tmp_path = os.path.join(os.environ.get('TEMP', '.'), f'upload_{int(time.time())}.pcap')
    f.save(tmp_path)

    try:
        df, err = extract_features_from_pcap(tmp_path)
        if err:
            return jsonify({'error': err}), 400

        results = predict_dataframe(df)
        nb_anomalies = sum(1 for r in results if r['prediction'] == 'ANOMALIE')
        nb_critical  = sum(1 for r in results if r['alert_level'] == 'CRITICAL')

        return jsonify({
            'total'       : len(results),
            'anomalies'   : nb_anomalies,
            'normal'      : len(results) - nb_anomalies,
            'critical'    : nb_critical,
            'anomaly_rate': round(nb_anomalies / max(len(results),1) * 100, 1),
            'connections' : results,
        })
    finally:
        if os.path.exists(tmp_path):
            os.remove(tmp_path)

if __name__ == '__main__':
    print("IDS App → http://localhost:5000")
    app.run(debug=False, host='0.0.0.0', port=5000)