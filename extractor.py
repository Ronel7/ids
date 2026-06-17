"""
═══════════════════════════════════════════════════════════════
  Extracteur de features NSL-KDD depuis un fichier .pcap
  ─────────────────────────────────────────────────────────────
  Entrée  : fichier .pcap (tcpdump, Wireshark)
  Sortie  : CSV avec les 41 features NSL-KDD prêtes pour le ML

  Dépendances : pip install scapy pandas numpy
  Usage      : python pcap_feature_extractor.py capture.pcap
═══════════════════════════════════════════════════════════════
"""

import sys
import os
import pandas as pd
import numpy as np
from collections import defaultdict

try:
    from scapy.all import rdpcap, IP, TCP, UDP, ICMP, Raw
except ImportError:
    print("Installe scapy : pip install scapy")
    sys.exit(1)

# CONFIG
PCAP_PATH  = sys.argv[1] if len(sys.argv) > 1 else "capture_simulee.pcap"
OUTPUT_CSV = PCAP_PATH.replace(".pcap", "_features.csv")
WINDOW_2S  = 2.0    # secondes pour les features count/srv_count
WINDOW_100 = 100    # nb de connexions pour les features dst_host_*

# MAPPING port → service (nomenclature NSL-KDD)

PORT_SERVICE = {
    20:'ftp_data', 21:'ftp', 22:'ssh', 23:'telnet', 25:'smtp',
    37:'time', 53:'domain', 67:'urp_i', 68:'urp_i', 69:'tftp_u',
    79:'finger', 80:'http', 110:'pop_3', 111:'sunrpc', 113:'auth',
    119:'nntp', 123:'ntp_u', 137:'netbios_ns', 138:'netbios_dgm',
    139:'netbios_ssn', 143:'imap4', 161:'other', 179:'bgp',
    389:'ldap', 443:'http_443', 445:'netbios_ssn', 512:'exec',
    513:'login', 514:'shell', 515:'printer', 520:'other',
    540:'uucp', 543:'klogin', 544:'kshell', 587:'smtp',
    993:'imap4', 995:'pop_3', 1080:'other', 3306:'other',
    5432:'other', 5900:'other', 6379:'other', 8080:'http',
    8443:'http_443', 27017:'other',
}

def port_to_service(port, proto='tcp'):
    """Convertit un port en nom de service NSL-KDD."""
    if proto == 'icmp':
        return 'eco_i'
    return PORT_SERVICE.get(port, 'private' if port > 1023 else 'other')

# DÉDUCTION DU FLAG TCP (logique NSL-KDD)

def deduce_flag(flags_seq, has_data_fwd, has_data_bwd):
    """
    Reconstitue le flag NSL-KDD depuis la séquence de flags TCP observés.

    Flags NSL-KDD :
      SF    = SYN + FIN → connexion complète et normale
      S0    = SYN seul, pas de réponse → SYN flood / connexion abandonnée
      REJ   = SYN + RST immédiat → port fermé
      RSTO  = RST envoyé par le client après ouverture
      RSTR  = RST envoyé par le serveur après ouverture
      S1/S2/S3 = connexion ouverte mais non terminée proprement
      SH    = SYN + FIN sans échange de données
      OTH   = autre cas
    """
    f = set(flags_seq)
    has_syn  = 'S'  in f
    has_sa   = 'SA' in f
    has_fin  = 'FA' in f or 'F' in f
    has_rst  = 'R'  in f or 'RA' in f

    if has_syn and not has_sa and not has_rst:
        return 'S0'     # SYN sans réponse → flood ou timeout

    if has_syn and has_sa and has_fin and not has_rst:
        return 'SF'     # connexion complète normale

    if has_syn and has_rst and not has_sa:
        return 'REJ'    # port fermé

    if has_syn and has_sa and has_rst:
        return 'RSTO' if has_data_fwd else 'RSTR'

    if has_syn and has_sa and not has_fin:
        return 'S1'     # connexion ouverte non terminée

    if has_syn and has_fin and not has_sa:
        return 'SH'     # SYN + FIN sans données

    return 'OTH'

def is_syn_error(flag):
    """True si la connexion a une erreur SYN (S0, S1, S2, S3)."""
    return flag in ('S0', 'S1', 'S2', 'S3')

def is_reject(flag):
    """True si la connexion a été rejetée (REJ, RSTR, RSTOS0)."""
    return flag in ('REJ', 'RSTR', 'RSTOS0')


# ÉTAPE 1 : Lire le pcap et grouper par connexion

def load_and_group(pcap_path):
    """
    Lit le fichier pcap et regroupe les paquets par connexion.
    Une connexion TCP = même (src_ip, dst_ip, src_port, dst_port).
    Retourne un dict : conn_key → liste de paquets.
    """
    print(f"  Lecture de {"C:/Users/Elitebook 840 G6/Downloads/ids/capture_simulee.pcap"}...")
    pkts = rdpcap(pcap_path)
    print(f"  {len(pkts)} paquets lus")

    connections = defaultdict(list)
    for pkt in pkts:
        if not pkt.haslayer(IP):
            continue

        ip = pkt[IP]

        if pkt.haslayer(TCP):
            tcp = pkt[TCP]
            # Clé canonique pour regrouper les deux sens de la connexion
            key = tuple(sorted([(ip.src, tcp.sport), (ip.dst, tcp.dport)]))
            key = ('tcp', key)
        elif pkt.haslayer(ICMP):
            key = ('icmp', (ip.src, ip.dst))
        else:
            continue  # on ignore les protocoles non TCP/ICMP

        connections[key].append(pkt)

    print(f"  {len(connections)} connexions reconstituées")
    return connections

# ─────────────────────────────────────────────────────────────
# ÉTAPE 2 : Extraire les features basiques et de contenu
# ─────────────────────────────────────────────────────────────
def extract_basic_features(conn_key, conn_pkts):
    """
    Extrait les 22 features basiques et de contenu (niveau 1 & 2).
    Ces features viennent d'une seule connexion, sans contexte extérieur.
    """
    proto_tag = conn_key[0]
    conn_pkts = sorted(conn_pkts, key=lambda p: p.time)

    first_pkt = conn_pkts[0]
    ip0 = first_pkt[IP]

    # ── Déterminer l'initiateur (celui qui envoie le SYN) ──
    src_ip, src_port, dst_ip, dst_port = None, None, None, None
    if proto_tag == 'tcp':
        for p in conn_pkts:
            tcp = p[TCP]
            # SYN sans ACK = paquet d'ouverture
            if (tcp.flags & 0x02) and not (tcp.flags & 0x10):
                src_ip, src_port = p[IP].src, tcp.sport
                dst_ip, dst_port = p[IP].dst, tcp.dport
                break
    if src_ip is None:
        src_ip, dst_ip = ip0.src, ip0.dst
        src_port = conn_pkts[0][TCP].sport if proto_tag == 'tcp' else 0
        dst_port = conn_pkts[0][TCP].dport if proto_tag == 'tcp' else 0

    # ── duration ──
    # Différence entre le timestamp du dernier et du premier paquet
    t_start  = conn_pkts[0].time
    t_end    = conn_pkts[-1].time
    duration = round(t_end - t_start, 6)

    # ── protocol_type ──
    protocol_type = proto_tag  # 'tcp', 'udp', 'icmp'

    # ── service ──
    service = port_to_service(dst_port, proto_tag)

    # ── src_bytes et dst_bytes ──
    # On compte les octets de payload (sans les en-têtes IP/TCP)
    src_bytes = 0
    dst_bytes = 0
    for p in conn_pkts:
        if not p.haslayer(TCP): continue
        payload_len = len(p[TCP].payload)
        if p[IP].src == src_ip:
            src_bytes += payload_len
        else:
            dst_bytes += payload_len

    # ── flag TCP ──
    flags_seen   = []
    has_data_fwd = False
    has_data_bwd = False
    for p in conn_pkts:
        if not p.haslayer(TCP): continue
        f = p[TCP].flags
        flag_str = ""
        if f & 0x02: flag_str += "S"
        if f & 0x10: flag_str += "A"
        if f & 0x08: flag_str += "P"
        if f & 0x01: flag_str += "F"
        if f & 0x04: flag_str += "R"
        if flag_str:
            flags_seen.append(flag_str)
        if len(p[TCP].payload) > 0:
            if p[IP].src == src_ip: has_data_fwd = True
            else:                   has_data_bwd = True

    flag = deduce_flag(flags_seen, has_data_fwd, has_data_bwd) if flags_seen else 'OTH'

    # ── land ──
    # 1 si IP source = IP destination (rare, signe d'attaque land)
    land = 1 if (src_ip == dst_ip and src_port == dst_port) else 0

    # ── wrong_fragment ──
    # Fragments IP avec payload vide (anormal)
    wrong_fragment = sum(
        1 for p in conn_pkts
        if p.haslayer(IP) and p[IP].frag != 0
        and p.haslayer(TCP) and len(p[TCP].payload) == 0
    )

    # ── urgent ──
    # Paquets avec flag URG activé
    urgent = sum(
        1 for p in conn_pkts
        if p.haslayer(TCP) and (p[TCP].flags & 0x20)
    )

    # ── Inspection du payload (features de contenu) ──
    full_payload = b""
    for p in conn_pkts:
        if p.haslayer(Raw):
            full_payload += bytes(p[Raw].load)
    payload_str = full_payload.decode('utf-8', errors='ignore').lower()

    # logged_in : session authentifiée détectée ?
    logged_in = 1 if any(kw in payload_str for kw in
                         ['cookie:', '200 ok', 'welcome', 'logged in',
                          'authentication successful']) else 0

    # num_failed_logins : tentatives d'auth échouées dans le payload
    num_failed_logins = (
        payload_str.count('permission denied') +
        payload_str.count('authentication failure') +
        payload_str.count('login incorrect') +
        payload_str.count('access denied')
    )

    # hot : accès à des ressources sensibles
    hot_keywords = ['/etc/passwd', '/etc/shadow', '/root', 'chmod 777',
                    '/etc/hosts', '/.ssh/', 'sudo ', 'su -']
    hot = sum(1 for kw in hot_keywords if kw in payload_str)

    # root_shell : shell root ouvert ?
    root_shell = 1 if ('root@' in payload_str or '# ' in payload_str
                        or '/bin/sh' in payload_str) else 0

    # num_compromised : erreurs système graves
    num_compromised = (
        payload_str.count('buffer overflow') +
        payload_str.count('segfault') +
        payload_str.count('core dumped')
    )

    # autres features contenu
    su_attempted       = 1 if ('su -' in payload_str or 'sudo' in payload_str) else 0
    num_root           = payload_str.count('root')
    num_file_creations = payload_str.count('creat(') + payload_str.count('open(')
    num_shells         = payload_str.count('/bin/sh') + payload_str.count('/bin/bash')
    num_access_files   = payload_str.count('/etc') + payload_str.count('/var/log')
    num_outbound_cmds  = 0  # nécessite analyse applicative approfondie
    is_host_login      = 1 if any(kw in payload_str for kw in
                                   ['rlogin', 'rsh', 'rexec']) else 0
    is_guest_login     = 1 if any(kw in payload_str for kw in
                                   ['guest', 'anonymous']) else 0

    return {
        # Features basiques
        'duration'          : duration,
        'protocol_type'     : protocol_type,
        'service'           : service,
        'flag'              : flag,
        'src_bytes'         : src_bytes,
        'dst_bytes'         : dst_bytes,
        'land'              : land,
        'wrong_fragment'    : wrong_fragment,
        'urgent'            : urgent,
        # Features contenu
        'hot'               : hot,
        'num_failed_logins' : num_failed_logins,
        'logged_in'         : logged_in,
        'num_compromised'   : num_compromised,
        'root_shell'        : root_shell,
        'su_attempted'      : su_attempted,
        'num_root'          : num_root,
        'num_file_creations': num_file_creations,
        'num_shells'        : num_shells,
        'num_access_files'  : num_access_files,
        'num_outbound_cmds' : num_outbound_cmds,
        'is_host_login'     : is_host_login,
        'is_guest_login'    : is_guest_login,
        # Métadonnées internes pour calculer les features trafic
        '_src_ip'           : src_ip,
        '_dst_ip'           : dst_ip,
        '_dst_port'         : dst_port,
        '_t_start'          : t_start,
        '_flag'             : flag,
    }

# ─────────────────────────────────────────────────────────────
# ÉTAPE 3 : Features trafic (fenêtres glissantes)
# ─────────────────────────────────────────────────────────────
def add_traffic_features(df):
    """
    Calcule les 19 features de trafic basées sur des fenêtres glissantes.

    Fenêtre A — 2 secondes :
      count, srv_count, serror_rate, srv_serror_rate,
      rerror_rate, srv_rerror_rate, same_srv_rate,
      diff_srv_rate, srv_diff_host_rate

    Fenêtre B — 100 dernières connexions vers même hôte :
      dst_host_count, dst_host_srv_count,
      dst_host_same_srv_rate, dst_host_diff_srv_rate,
      dst_host_same_src_port_rate, dst_host_srv_diff_host_rate,
      dst_host_serror_rate, dst_host_srv_serror_rate,
      dst_host_rerror_rate, dst_host_srv_rerror_rate
    """
    df = df.sort_values('_t_start').reset_index(drop=True)
    results = []

    for i, row in df.iterrows():
        t_now    = row['_t_start']
        dst_ip   = row['_dst_ip']
        dst_port = row['_dst_port']
        svc      = row['service']
        src_ip   = row['_src_ip']

        # ── Fenêtre 2 secondes : connexions vers même dst_ip ──
        win2 = df[
            (df['_t_start'] >= t_now - WINDOW_2S) &
            (df['_t_start'] <= t_now)
        ]
        same_dst = win2[win2['_dst_ip'] == dst_ip]
        n2       = max(len(same_dst), 1)

        # count / srv_count
        count     = n2
        srv_count = len(same_dst[same_dst['service'] == svc])

        # taux d'erreurs SYN dans la fenêtre
        serr_mask = same_dst['_flag'].apply(is_syn_error)
        rerr_mask = same_dst['_flag'].apply(is_reject)
        serror_rate = round(serr_mask.sum() / n2, 3)
        rerror_rate = round(rerr_mask.sum() / n2, 3)

        # même calcul sur le sous-ensemble du même service
        srv_same  = same_dst[same_dst['service'] == svc]
        n_srv     = max(len(srv_same), 1)
        srv_serror_rate = round(srv_same['_flag'].apply(is_syn_error).sum() / n_srv, 3)
        srv_rerror_rate = round(srv_same['_flag'].apply(is_reject).sum()     / n_srv, 3)

        same_srv_rate      = round(len(same_dst[same_dst['service'] == svc]) / n2, 3)
        diff_srv_rate      = round(len(same_dst[same_dst['service'] != svc]) / n2, 3)
        srv_diff_host_rate = round(
            len(srv_same[srv_same['_dst_ip'] != dst_ip]) / n_srv, 3
        )

        # ── Fenêtre 100 connexions : même dst_ip ──
        idx_start = max(0, i - WINDOW_100 + 1)
        win100    = df.iloc[idx_start : i + 1]
        same_host = win100[win100['_dst_ip'] == dst_ip]
        n100      = max(len(same_host), 1)

        dst_host_count    = n100
        same_svc_host     = same_host[same_host['service'] == svc]
        dst_host_srv_count = len(same_svc_host)

        dst_host_same_srv_rate = round(len(same_svc_host) / n100, 3)
        dst_host_diff_srv_rate = round(
            len(same_host[same_host['service'] != svc]) / n100, 3
        )
        dst_host_same_src_port_rate = round(
            len(same_host[same_host['_dst_port'] == dst_port]) / n100, 3
        )

        n_srv100 = max(len(same_svc_host), 1)
        dst_host_srv_diff_host_rate = round(
            len(same_svc_host[same_svc_host['_dst_ip'] != dst_ip]) / n_srv100, 3
        )

        # taux d'erreurs sur les 100 connexions vers cet hôte
        h_serr = same_host['_flag'].apply(is_syn_error).sum()
        h_rerr = same_host['_flag'].apply(is_reject).sum()
        dst_host_serror_rate = round(h_serr / n100, 3)
        dst_host_rerror_rate = round(h_rerr / n100, 3)

        sv_serr = same_svc_host['_flag'].apply(is_syn_error).sum()
        sv_rerr = same_svc_host['_flag'].apply(is_reject).sum()
        dst_host_srv_serror_rate = round(sv_serr / n_srv100, 3)
        dst_host_srv_rerror_rate = round(sv_rerr / n_srv100, 3)

        results.append({
            'count'                        : count,
            'srv_count'                    : srv_count,
            'serror_rate'                  : serror_rate,
            'srv_serror_rate'              : srv_serror_rate,
            'rerror_rate'                  : rerror_rate,
            'srv_rerror_rate'              : srv_rerror_rate,
            'same_srv_rate'                : same_srv_rate,
            'diff_srv_rate'                : diff_srv_rate,
            'srv_diff_host_rate'           : srv_diff_host_rate,
            'dst_host_count'               : dst_host_count,
            'dst_host_srv_count'           : dst_host_srv_count,
            'dst_host_same_srv_rate'       : dst_host_same_srv_rate,
            'dst_host_diff_srv_rate'       : dst_host_diff_srv_rate,
            'dst_host_same_src_port_rate'  : dst_host_same_src_port_rate,
            'dst_host_srv_diff_host_rate'  : dst_host_srv_diff_host_rate,
            'dst_host_serror_rate'         : dst_host_serror_rate,
            'dst_host_srv_serror_rate'     : dst_host_srv_serror_rate,
            'dst_host_rerror_rate'         : dst_host_rerror_rate,
            'dst_host_srv_rerror_rate'     : dst_host_srv_rerror_rate,
        })

    traffic_df = pd.DataFrame(results, index=df.index)
    return pd.concat([df, traffic_df], axis=1)

# ─────────────────────────────────────────────────────────────
# PIPELINE PRINCIPAL
# ─────────────────────────────────────────────────────────────
NSL_KDD_COLS = [
    'duration','protocol_type','service','flag','src_bytes','dst_bytes',
    'land','wrong_fragment','urgent','hot','num_failed_logins','logged_in',
    'num_compromised','root_shell','su_attempted','num_root',
    'num_file_creations','num_shells','num_access_files','num_outbound_cmds',
    'is_host_login','is_guest_login','count','srv_count','serror_rate',
    'srv_serror_rate','rerror_rate','srv_rerror_rate','same_srv_rate',
    'diff_srv_rate','srv_diff_host_rate','dst_host_count','dst_host_srv_count',
    'dst_host_same_srv_rate','dst_host_diff_srv_rate',
    'dst_host_same_src_port_rate','dst_host_srv_diff_host_rate',
    'dst_host_serror_rate','dst_host_srv_serror_rate',
    'dst_host_rerror_rate','dst_host_srv_rerror_rate',
]

def run(pcap_path, output_csv):
    print("=" * 60)
    print("  Extracteur de features NSL-KDD depuis pcap")
    print("=" * 60)

    # 1. Charger et grouper les paquets
    print("\n[1/3] Chargement et groupement...")
    connections = load_and_group(pcap_path)

    # 2. Extraire les features basiques et contenu
    print("\n[2/3] Extraction des features basiques et contenu...")
    records = []
    for conn_key, conn_pkts in connections.items():
        try:
            rec = extract_basic_features(conn_key, conn_pkts)
            records.append(rec)
        except Exception as e:
            pass  # ignorer les connexions malformées

    df = pd.DataFrame(records)
    print(f"  {len(df)} connexions traitées, 22 features extraites")

    # 3. Calculer les features trafic (fenêtres glissantes)
    print("\n[3/3] Calcul des features trafic (fenêtres glissantes)...")
    df = add_traffic_features(df)
    print(f"  19 features trafic ajoutées → total : 41 features")

    # 4. Sauvegarder
    result = df[NSL_KDD_COLS].copy()
    result.to_csv(output_csv, index=False)

    print(f"\n{'=' * 60}")
    print(f"  ✓ Dataset sauvegardé : {output_csv}")
    print(f"  Dimensions : {result.shape[0]} connexions × {result.shape[1]} features")
    print("=" * 60)

    # Résumé par type de connexion détecté
    print("\n  Résumé des flags détectés :")
    print(result['flag'].value_counts().to_string())
    print("\n  Résumé des services :")
    print(result['service'].value_counts().head(10).to_string())

    return result

if __name__ == "__main__":
    result = run(PCAP_PATH, OUTPUT_CSV)
    print(f"\n  Prêt pour le modèle : charger {OUTPUT_CSV} dans le pipeline ML")