"""
Script de generación de datos simulados para el Pipeline de Ciberseguridad con IA.
Genera todos los datasets necesarios para ejecutar los notebooks 01-08.
"""
import numpy as np
import pandas as pd
import os

np.random.seed(42)
os.makedirs('data', exist_ok=True)

# ============================================================
# 1. NETWORK TRAFFIC (Capítulo 3 - Detección de Amenazas)
# ============================================================
print("Generando: data/network_traffic.csv ...")
n_normal = 5000
n_anomaly = 250

normal = pd.DataFrame({
    'bytes_sent':  np.random.exponential(500, n_normal).astype(int),
    'bytes_recv':  np.random.exponential(800, n_normal).astype(int),
    'duration':    np.random.exponential(30, n_normal).round(2),
    'protocol':    np.random.choice(['TCP', 'UDP', 'ICMP'], n_normal, p=[0.7, 0.25, 0.05]),
    'src_port':    np.random.randint(1024, 65535, n_normal),
    'dst_port':    np.random.choice([80, 443, 53, 22, 8080], n_normal),
    'label':       0
})

anomaly = pd.DataFrame({
    'bytes_sent':  np.random.exponential(5000, n_anomaly).astype(int),
    'bytes_recv':  np.random.exponential(50, n_anomaly).astype(int),
    'duration':    np.random.exponential(200, n_anomaly).round(2),
    'protocol':    np.random.choice(['TCP', 'UDP', 'ICMP'], n_anomaly, p=[0.3, 0.3, 0.4]),
    'src_port':    np.random.randint(1, 1024, n_anomaly),
    'dst_port':    np.random.choice([4444, 31337, 6667, 9999], n_anomaly),
    'label':       1
})

df_network = pd.concat([normal, anomaly], ignore_index=True).sample(frac=1, random_state=42).reset_index(drop=True)
df_network.to_csv('data/network_traffic.csv', index=False)
print(f"  [OK] {len(df_network)} registros (Normal: {n_normal}, Anomalía: {n_anomaly})")


# ============================================================
# 2. FILE FEATURES - Malware PE (Capítulo 4 - Detección de Malware)
# ============================================================
print("Generando: data/file_features.csv ...")
n_benign = 800
n_malicious = 200

benign = pd.DataFrame({
    'entry_point':        np.random.randint(4096, 65536, n_benign),
    'image_base':         np.full(n_benign, 4194304),
    'size_of_image':      np.random.randint(50000, 500000, n_benign),
    'size_code_section':  np.random.randint(10000, 200000, n_benign),
    'dll_flag':           np.random.choice([0x8160, 0x8140, 0x8120], n_benign),
    'num_sections':       np.random.choice([3, 4, 5, 6], n_benign, p=[0.1, 0.4, 0.35, 0.15]),
    'entropia_max':       np.random.uniform(4.0, 6.5, n_benign).round(4),
    'entropia_media':     np.random.uniform(3.5, 5.8, n_benign).round(4),
    'num_importaciones':  np.random.randint(50, 400, n_benign),
    'num_dlls_importadas':np.random.randint(5, 25, n_benign),
    'num_exportaciones':  np.random.randint(0, 10, n_benign),
    'file_size':          np.random.randint(50000, 2000000, n_benign),
    'label':              0
})

malicious = pd.DataFrame({
    'entry_point':        np.random.randint(0, 4096, n_malicious),
    'image_base':         np.random.choice([4194304, 268435456, 65536], n_malicious),
    'size_of_image':      np.random.randint(5000, 100000, n_malicious),
    'size_code_section':  np.random.randint(500, 15000, n_malicious),
    'dll_flag':           np.random.choice([0x0000, 0x0040, 0x8160], n_malicious, p=[0.5, 0.3, 0.2]),
    'num_sections':       np.random.choice([1, 2, 3, 8, 10], n_malicious, p=[0.2, 0.3, 0.2, 0.2, 0.1]),
    'entropia_max':       np.random.uniform(6.5, 8.0, n_malicious).round(4),
    'entropia_media':     np.random.uniform(5.5, 7.8, n_malicious).round(4),
    'num_importaciones':  np.random.randint(2, 30, n_malicious),
    'num_dlls_importadas':np.random.randint(1, 5, n_malicious),
    'num_exportaciones':  np.random.randint(0, 2, n_malicious),
    'file_size':          np.random.randint(5000, 80000, n_malicious),
    'label':              1
})

df_pe = pd.concat([benign, malicious], ignore_index=True).sample(frac=1, random_state=42).reset_index(drop=True)
df_pe.to_csv('data/file_features.csv', index=False)
print(f"  [OK] {len(df_pe)} registros (Benign: {n_benign}, Malicious: {n_malicious})")


# ============================================================
# 3. INCIDENT DATA (Capítulo 5 - Respuesta a Incidentes)
# ============================================================
print("Generando: data/incident_data.csv ...")
n_inc = 2000
severities = np.random.choice([0, 1, 2, 3], n_inc, p=[0.40, 0.30, 0.20, 0.10])

records_inc = []
for sev in severities:
    if sev == 0:
        row = {'num_hosts_afectados': np.random.randint(1, 2),
               'tipo_evento_cod': np.random.choice([1, 2]),
               'bytes_exfiltrados': np.random.randint(0, 500),
               'duracion_seg': np.random.randint(1, 30),
               'privilegios_elevados': 0}
    elif sev == 1:
        row = {'num_hosts_afectados': np.random.randint(1, 5),
               'tipo_evento_cod': np.random.choice([2, 3, 4]),
               'bytes_exfiltrados': np.random.randint(500, 10000),
               'duracion_seg': np.random.randint(15, 120),
               'privilegios_elevados': np.random.choice([0, 1], p=[0.7, 0.3])}
    elif sev == 2:
        row = {'num_hosts_afectados': np.random.randint(3, 15),
               'tipo_evento_cod': np.random.choice([4, 5, 6]),
               'bytes_exfiltrados': np.random.randint(10000, 500000),
               'duracion_seg': np.random.randint(60, 600),
               'privilegios_elevados': np.random.choice([0, 1], p=[0.3, 0.7])}
    else:
        row = {'num_hosts_afectados': np.random.randint(10, 50),
               'tipo_evento_cod': np.random.choice([5, 6, 7]),
               'bytes_exfiltrados': np.random.randint(500000, 5000000),
               'duracion_seg': np.random.randint(300, 3600),
               'privilegios_elevados': 1}
    row['severity'] = sev
    records_inc.append(row)

df_inc = pd.DataFrame(records_inc).sample(frac=1, random_state=42).reset_index(drop=True)
df_inc.to_csv('data/incident_data.csv', index=False)
print(f"  [OK] {len(df_inc)} registros (Bajo:{(df_inc['severity']==0).sum()}, Medio:{(df_inc['severity']==1).sum()}, Alto:{(df_inc['severity']==2).sum()}, Crítico:{(df_inc['severity']==3).sum()})")


# ============================================================
# 4. USER ACTIVITY LOGS (Capítulo 6 - Análisis de Comportamiento UBA)
# ============================================================
print("Generando: data/user_activity_logs.csv ...")
usuarios = ['ana.garcia', 'carlos.lopez', 'maria.torres', 'juan.perez', 'lucia.diaz']
ips_corporativas = ['10.0.1.10', '10.0.1.11', '10.0.1.12', '10.0.1.20', '10.0.2.30']
ips_externas = ['45.33.32.156', '185.220.101.5', '91.219.236.10', '104.18.5.6']

registros_uba = []
for usuario in usuarios:
    hora_base = np.random.uniform(7.5, 9.5)
    hora_std = np.random.uniform(0.3, 1.0)
    bytes_base = np.random.uniform(5000, 50000)
    bytes_std = np.random.uniform(2000, 15000)
    ips_habituales = np.random.choice(ips_corporativas, size=2, replace=False).tolist()

    for _ in range(200):
        registros_uba.append({
            'user':          usuario,
            'hora_login':    round(np.clip(np.random.normal(hora_base, hora_std), 0, 23.99), 2),
            'ip_origen':     np.random.choice(ips_habituales),
            'bytes_sent':    int(np.clip(np.random.normal(bytes_base, bytes_std), 100, 500000)),
            'failed_logins': np.random.choice([0, 0, 0, 0, 1], p=[0.7, 0.1, 0.1, 0.05, 0.05]),
        })

    n_sospechoso = np.random.randint(5, 11)
    for _ in range(n_sospechoso):
        registros_uba.append({
            'user':          usuario,
            'hora_login':    round(np.random.uniform(0.5, 5.0), 2),
            'ip_origen':     np.random.choice(ips_externas),
            'bytes_sent':    int(np.random.uniform(300000, 900000000)),
            'failed_logins': np.random.randint(3, 15),
        })

df_uba = pd.DataFrame(registros_uba).sample(frac=1, random_state=42).reset_index(drop=True)
df_uba.to_csv('data/user_activity_logs.csv', index=False)
print(f"  [OK] {len(df_uba)} registros ({len(usuarios)} usuarios)")


# ============================================================
# RESUMEN FINAL
# ============================================================
print("\n" + "=" * 55)
print("  DATOS SIMULADOS GENERADOS EXITOSAMENTE")
print("=" * 55)
for f in sorted(os.listdir('data')):
    path = os.path.join('data', f)
    size = os.path.getsize(path)
    df_temp = pd.read_csv(path)
    print(f"  {f:<30} {len(df_temp):>6} filas  ({size:>10,} bytes)")
print("=" * 55)
