import io
import os
import hmac
import hashlib
from datetime import datetime, timedelta
import numpy as np
import pandas as pd
import streamlit as st
import matplotlib.pyplot as plt

# ---------------------------
# Configuración general
# ---------------------------
st.set_page_config(
    page_title="Mini-Lab IoT — Integridad & Capas",
    page_icon="🛡️",
    layout="wide"
)

# Estilos mínimos
st.markdown("""
<style>
.small { font-size:0.85rem; color:#666; }
.ok { color: #1b7f3b; font-weight:600; }
.bad { color: #b3002d; font-weight:600; }
.codebox { font-family: monospace; background:#0f1117; color:#eaeef3; padding:8px 10px; border-radius:8px; }
</style>
""", unsafe_allow_html=True)

# ---------------------------
# Utilidades de integridad
# ---------------------------

def get_secret_key():
    # Intenta leer de secrets; si no existe, crea una temporal de solo sesión
    tmp_env_key = st.session_state.get("_tmp_hmac_key")
    key = st.secrets.get("hmac_key", None)
    if key is None:
        if tmp_env_key is None:
            tmp_env_key = hashlib.sha256(os.urandom(64)).hexdigest()
            st.session_state["_tmp_hmac_key"] = tmp_env_key
        return tmp_env_key, False
    return str(key), True

def canonical_string(row: pd.Series) -> str:
    """
    Cadena canónica por registro: asegura orden estable de campos firmados.
    """
    # Campos mínimos
    ts = str(row.get("timestamp", ""))
    dev = str(row.get("device_id", ""))
    metric = str(row.get("metric", ""))
    value = str(row.get("value", ""))
    # Metadatos de capa (si existen)
    layer_tag = str(row.get("layer_tag", ""))  # 'perception'|'network'|'application' o vacío
    return "|".join([ts, dev, metric, value, layer_tag])

def hmac_sign(text: str, key: str) -> str:
    return hmac.new(key.encode("utf-8"), text.encode("utf-8"), hashlib.sha256).hexdigest()

def sign_dataframe(df: pd.DataFrame, key: str) -> pd.DataFrame:
    df2 = df.copy()
    if "layer_tag" not in df2.columns:
        df2["layer_tag"] = ""
    df2["signature"] = df2.apply(lambda r: hmac_sign(canonical_string(r), key), axis=1)
    return df2

def verify_dataframe(df_signed: pd.DataFrame, key: str) -> pd.DataFrame:
    dfv = df_signed.copy()
    expected = dfv.apply(lambda r: hmac_sign(canonical_string(r), key), axis=1)
    dfv["valid"] = (expected == dfv["signature"])
    return dfv

def merkle_root(hex_hashes: list[str]) -> str:
    """
    Merkle root simple sobre la lista de firmas hex (SHA256 sobre concatenaciones binarias).
    """
    if not hex_hashes:
        return ""
    level = [bytes.fromhex(h) for h in hex_hashes]
    while len(level) > 1:
        nxt = []
        for i in range(0, len(level), 2):
            left = level[i]
            right = level[i+1] if i+1 < len(level) else left
            nxt.append(hashlib.sha256(left + right).digest())
        level = nxt
    return level[0].hex()

def simulate_tamper(df: pd.DataFrame, layer: str, intensity: float, pct_rows: float, seed: int = 42) -> pd.DataFrame:
    """
    Simula manipulación en una capa:
    - perception: altera 'value' con ruido
    - network: altera orden/duplicados/timestamp jitter
    - application: cambia algunos 'metric' o redondea 'value'
    """
    rng = np.random.default_rng(seed)
    tampered = df.copy()
    n = len(tampered)
    k = max(1, int(n * pct_rows))
    idx = rng.choice(n, size=k, replace=False)

    if layer == "perception":
        noise = rng.normal(loc=0.0, scale=intensity, size=k)
        tampered.loc[tampered.index[idx], "value"] = tampered.loc[tampered.index[idx], "value"] + noise
        tampered.loc[tampered.index[idx], "layer_tag"] = "perception"

    elif layer == "network":
        # timestamp jitter y duplicado aleatorio
        jitter = rng.integers(low=-int(60*intensity), high=int(60*intensity)+1, size=k)
        base_ts = pd.to_datetime(tampered.loc[tampered.index[idx], "timestamp"], errors="coerce")
        tampered.loc[tampered.index[idx], "timestamp"] = (base_ts + pd.to_timedelta(jitter, unit="s")).astype(str)
        if k >= 2:
            dup_rows = tampered.iloc[idx[:k//2]]
            tampered = pd.concat([tampered, dup_rows], ignore_index=True)
        tampered = tampered.sample(frac=1.0, random_state=seed).reset_index(drop=True)
        tampered["layer_tag"] = tampered.get("layer_tag", "")
        # Marcar solo los tocados originales
        for i in idx:
            if i < len(tampered):
                tampered.at[i, "layer_tag"] = "network"

    elif layer == "application":
        # redondeo agresivo o cambio de métrica
        choose = rng.choice(["round", "rename"], size=k)
        rows = tampered.index[idx]
        for r, ch in zip(rows, choose):
            if ch == "round":
                tampered.at[r, "value"] = float(np.round(tampered.at[r, "value"], int(max(0, 1 - intensity))))
            else:
                tampered.at[r, "metric"] = str(tampered.at[r, "metric"]) + "_alt"
            tampered.at[r, "layer_tag"] = "application"

    return tampered

# ---------------------------
# Generación/entrada de datos
# ---------------------------

def generate_sample(n_devices=3, n_points=200, start=None):
    if start is None:
        start = datetime.utcnow() - timedelta(hours=1)
    rows = []
    metrics = ["temperature", "vibration", "pressure"]
    for d in range(n_devices):
        dev_id = f"dev-{d+1:02d}"
        t0 = start
        for i in range(n_points):
            ts = t0 + timedelta(seconds=i*15)
            metric = metrics[i % len(metrics)]
            base = {"temperature": 70.0, "vibration": 2.0, "pressure": 5.0}[metric]
            val = base + np.sin(i/12.0) * (0.5 if metric=="temperature" else 0.2) + np.random.normal(0, 0.02)
            rows.append([ts.isoformat(), dev_id, metric, float(val)])
    df = pd.DataFrame(rows, columns=["timestamp","device_id","metric","value"])
    return df

# ---------------------------
# UI
# ---------------------------

st.title("🛡️ Mini-Lab IoT — Integridad & Capas")
st.caption("Firma y verificación HMAC por registro • Simulación de manipulación por capa • Visualización con matplotlib • Raíz Merkle opcional")

with st.sidebar:
    st.header("⚙️ Configuración")
    key, from_secrets = get_secret_key()
    if from_secrets:
        st.markdown("**Clave HMAC**: leída de *Streamlit Secrets*. ✅")
    else:
        st.markdown("**Clave HMAC**: temporal de sesión (usa *Secrets* en producción). ⚠️")
    st.code(key[:8] + "..." + key[-8:], language="text")

    st.divider()
    mode = st.radio("Modo de trabajo", ["🔧 Generar datos demo", "📤 Subir CSV"], index=0)

    st.markdown("**Formato esperado CSV**: `timestamp,device_id,metric,value`", help="timestamp ISO-8601, value numérico.")

# Entrada de datos
if mode == "🔧 Generar datos demo":
    c1, c2, c3 = st.columns(3)
    with c1:
        ndev = st.number_input("Nº dispositivos", 1, 20, 3, 1)
    with c2:
        npts = st.number_input("Puntos por dispositivo", 50, 2000, 200, 50)
    with c3:
        seed = st.number_input("Semilla aleatoria", 0, 9999, 42, 1)
    rng = np.random.default_rng(int(seed))
    base = generate_sample(n_devices=int(ndev), n_points=int(npts))
else:
    uploaded = st.file_uploader("Sube tu CSV", type=["csv"])
    if uploaded is None:
        st.info("Sube un CSV para continuar o cambia a *Generar datos demo* en la barra lateral.")
        st.stop()
    base = pd.read_csv(uploaded)
    expected_cols = {"timestamp","device_id","metric","value"}
    if not expected_cols.issubset(set(map(str.lower, base.columns))):
        st.error("El CSV debe incluir columnas: timestamp, device_id, metric, value")
        st.stop()
    # Normaliza nombres por si vienen capitalizados
    base.columns = [c.lower() for c in base.columns]

st.subheader("1) Datos de entrada")
st.dataframe(base.head(20), use_container_width=True)

# Firma del lote original
st.subheader("2) Firmado (HMAC por registro)")
colA, colB = st.columns([2,1], vertical_alignment="bottom")

with colB:
    with st.expander("Parámetros de firma"):
        include_layer_tag = st.checkbox("Incluir 'layer_tag' en la cadena canónica", value=True,
                                        help="Marca qué capa tocó el registro; vacía si sin alteración.")
layer_info = " (con layer_tag)" if include_layer_tag else ""
if not include_layer_tag:
    base_no_tag = base.copy()
    if "layer_tag" in base_no_tag.columns:
        base_no_tag = base_no_tag.drop(columns=["layer_tag"])
    base_to_sign = base_no_tag
else:
    base_to_sign = base.assign(layer_tag="")

signed_base = sign_dataframe(base_to_sign, key)
st.success(f"✅ Lote firmado{layer_info}. Registros: {len(signed_base)}")
st.dataframe(signed_base.head(20), use_container_width=True)

# Merkle root opcional
with st.expander("🔗 Merkle root del lote firmado (opcional)"):
    root = merkle_root(list(signed_base["signature"].values))
    st.markdown("**Merkle Root:**")
    st.code(root if root else "(vacío)", language="text")
    st.caption("Ancla este hash fuera del sistema (p.ej., ticket interno, email a auditoría, etc.).")

# Simulación de manipulación
st.subheader("3) Simular manipulación por capa")
cc1, cc2, cc3, cc4 = st.columns([1.2,1,1,1])
with cc1:
    tamper_layer = st.selectbox("Capa a manipular", ["perception", "network", "application"])
with cc2:
    pct = st.slider("% de filas afectadas", 1, 50, 10, 1)
with cc3:
    intensity = st.slider("Intensidad", 1, 20, 5, 1)
with cc4:
    seed2 = st.number_input("Semilla", 0, 9999, 7, 1)

if st.button("💥 Aplicar manipulación"):
    tampered = simulate_tamper(signed_base, tamper_layer, intensity=float(intensity), pct_rows=pct/100.0, seed=int(seed2))
    st.session_state["tampered"] = tampered
    st.toast(f"Manipulación simulada en capa '{tamper_layer}'.", icon="⚠️")

tampered = st.session_state.get("tampered", signed_base.copy())
st.dataframe(tampered.head(20), use_container_width=True)

# Verificación
st.subheader("4) Verificación de integridad")
verified = verify_dataframe(tampered, key)
ok = verified["valid"].sum()
bad = len(verified) - ok

cA, cB = st.columns(2)
with cA:
    st.markdown(f"**Resultado:** <span class='ok'>OK {ok}</span> / <span class='bad'>ALTERADOS {bad}</span>", unsafe_allow_html=True)
with cB:
    st.download_button("⬇️ Exportar CSV verificado", data=verified.to_csv(index=False).encode("utf-8"),
                       file_name="iot_verified.csv", mime="text/csv")

with st.expander("Ver filas alteradas"):
    st.dataframe(verified[~verified["valid"]].head(200), use_container_width=True)

# Visualización (matplotlib)
st.subheader("5) Visualización")
vc1, vc2 = st.columns([1,1])
with vc1:
    dev_choice = st.selectbox("Dispositivo", sorted(verified["device_id"].unique().tolist()))
with vc2:
    metric_choice = st.selectbox("Métrica", sorted(verified["metric"].unique().tolist()))

plot_df = verified[(verified["device_id"]==dev_choice) & (verified["metric"]==metric_choice)].copy()
# parse timestamps robustamente
plot_df["ts"] = pd.to_datetime(plot_df["timestamp"], errors="coerce")

fig = plt.figure(figsize=(10, 4.5))
plt.plot(plot_df["ts"], plot_df["value"], linewidth=1.5, label="Valor")
if "valid" in plot_df.columns:
    # Pintar puntos rojos en alterados (sin especificar color fijo, usamos marker y anotación)
    bad_pts = plot_df[~plot_df["valid"]]
    if len(bad_pts) > 0:
        # Para cumplir la restricción: no fijamos color; solo marcador distinto
        plt.scatter(bad_pts["ts"], bad_pts["value"], marker="x", s=30, label="Alterado")
plt.title(f"{dev_choice} · {metric_choice}")
plt.xlabel("Tiempo")
plt.ylabel("Valor")
plt.legend()
plt.tight_layout()
st.pyplot(fig)

st.divider()
st.markdown("### 📚 Notas didácticas")
st.markdown("""
- **Cadena canónica** firmada por registro: `timestamp|device_id|metric|value|layer_tag`.
- **layer_tag** refleja en qué **capa** se alteró el dato: *perception* (sensor/edge), *network* (transporte), *application* (plataforma).
- Si cualquier campo cambia **después** de firmar, la **verificación falla**.
- **Merkle Root** del lote permite anclar un único hash representativo fuera del sistema (auditoría, registros, etc.).
- La clave HMAC **no debe** residir en el código ni en el CSV: se gestiona con **Streamlit Secrets**.
""")

st.caption("© 2025 — Mini-Lab IoT Integridad & Capas. Construido con Streamlit + matplotlib (sin seaborn).")
