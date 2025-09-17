import time, os, hmac, hashlib
from collections import deque
import numpy as np
import streamlit as st
import matplotlib.pyplot as plt

# ---------- Configuración ----------
st.set_page_config(page_title="Mini-Lab IoT: Integridad & Capas", layout="wide")
st.title("Mini-Lab IoT — Integridad de datos & Capas")
st.caption("Sesión 1: sensor→canal→verificación | Sesión 2: capas IoT | Sesión 3: Caso & entregables")

np.random.seed(7)

# ---------- Sensor y canal ----------
def sensor_temp(base=25.0, noise=0.3, drift=0.002, t=0):
    """Temperatura base + ruido gaussiano + deriva lenta."""
    return base + np.random.normal(0, noise) + drift * t

class Canal:
    def __init__(self, loss_prob=0.05, min_ms=20, max_ms=120, tamper=False, tamper_bias=10.0):
        self.loss_prob = loss_prob
        self.min_ms = min_ms
        self.max_ms = max_ms
        self.tamper = tamper
        self.tamper_bias = tamper_bias

    def enviar(self, valor):
        if np.random.rand() < self.loss_prob:
            return None, None
        lat = np.random.uniform(self.min_ms, self.max_ms)
        v = valor + self.tamper_bias if self.tamper else valor
        return v, lat

# ---------- Hash/HMAC ----------
SECRET = st.secrets.get("HMAC_SECRET", os.urandom(16))

def sha256_str(s: str) -> str:
    return hashlib.sha256(s.encode()).hexdigest()

def hmac_sha256(msg: str, key: bytes=SECRET) -> str:
    return hmac.new(key, msg.encode(), hashlib.sha256).hexdigest()

# ---------- Tabs ----------
tab1, tab2, tab3 = st.tabs(["Sesión 1 · Integridad (HMAC)", "Sesión 2 · Capas IoT", "Caso & Entregables"])

# ---------- Sesión 1 ----------
with tab1:
    st.subheader("Streaming de sensor + canal (latencia/pérdida) + tampering + verificación")
    colA, colB, colC, colD, colE = st.columns([1,1,1,1,1])
    dur_seg = colA.slider("Duración (s)", 5, 60, 20, step=5)
    perdida = colB.slider("Pérdida (prob.)", 0.0, 0.30, 0.05, step=0.01)
    tamper_on = colC.selectbox("Tampering", ["Sin manipulación", "Manipulado"])
    check = colD.selectbox("Integridad", ["Sin verificación", "SHA256", "HMAC"])
    tamper_bias = colE.slider("Tamper bias (°C)", 5, 20, 15, step=1)
    run = st.button("▶ Ejecutar simulación", type="primary")

    ph_chart = st.empty()
    ph_text = st.empty()
    csv_btn = st.empty()

    if run:
        canal_ok = Canal(loss_prob=perdida, tamper=False)
        canal_bad = Canal(loss_prob=perdida, tamper=True, tamper_bias=tamper_bias)
        c = canal_bad if tamper_on == "Manipulado" else canal_ok

        t0 = time.time()
        ts, rx_vals, verdict = [], [], []

        while time.time() - t0 < dur_seg:
            t = time.time() - t0
            raw = sensor_temp(t=t)
            msg = f"{raw:.2f}"

            sig = None
            if check == "SHA256":
                sig = sha256_str(msg)
            elif check == "HMAC":
                sig = hmac_sha256(msg)

            rx, lat = c.enviar(float(msg))
            if rx is None:
                time.sleep(0.05)
                continue

            ok = True
            if check == "SHA256":
                ok = (sha256_str(f"{rx:.2f}") == sig)
            elif check == "HMAC":
                ok = (hmac_sha256(f"{rx:.2f}") == sig)

            ts.append(t)
            rx_vals.append(rx)
            verdict.append(ok)

            fig, ax = plt.subplots()
            ax.plot(ts, rx_vals, marker='o', linewidth=1)
            ax.set_title("Temperatura recibida (°C)")
            ax.set_xlabel("Tiempo (s)")
            ax.set_ylabel("°C")
            bad_x = [tt for tt,v in zip(ts, verdict) if not v]
            bad_y = [vv for vv,v in zip(rx_vals, verdict) if not v]
            if bad_x:
                ax.scatter(bad_x, bad_y, s=60, edgecolor='k', c='r', label='Fallo integridad')
                ax.legend()
            ph_chart.pyplot(fig)

            total = len(verdict)
            malos = sum(1 for v in verdict if not v)
            ph_text.info(f"Samples: {total} | Fallos integridad: {malos} | Tampering: {tamper_on} | Verificación: {check}")
            time.sleep(0.25)

        import pandas as pd
        df = pd.DataFrame({"t": ts, "rx": rx_vals, "ok": verdict})
        csv_btn.download_button("⬇ Exportar CSV", df.to_csv(index=False), "resultados.csv", "text/csv")

    st.markdown("""
**Qué observar**  
- Tampering **OFF** → todo verde.  
- Tampering **ON** + **SHA256** → un atacante que recalcula el hash puede colarse.  
- Tampering **ON** + **HMAC** → fallos rojos (no se puede recomputar la firma sin clave).  
""")

# ---------- Sesión 2 ----------
with tab2:
    st.subheader("Capas IoT (Percepción, Red, Aplicación) · Trade-offs")
    proto = st.selectbox("Protocolo", ["WiFi","LoRaWAN","Zigbee","NB-IoT"], index=1)
    n_sens = st.slider("# Sensores", 1, 20, 4)
    alertas = st.checkbox("Alertas habilitadas", value=True)

    def perfil_protocolo(p):
        if p=="WiFi":   return dict(bw=54000, lat=30,  mAh=200)
        if p=="Zigbee": return dict(bw=250,   lat=60,  mAh=30)
        if p=="LoRaWAN":return dict(bw=5,     lat=500, mAh=5)
        if p=="NB-IoT": return dict(bw=60,    lat=300, mAh=10)

    def score_sistema(bw_kbps, lat_ms, energia_mAh_dia, n_sens, alertas):
        bw_need = n_sens * 2
        ok_bw = bw_kbps >= bw_need
        score = 0
        score += 2 if ok_bw else -2
        score += 2 if lat_ms < 200 else 0
        score += 2 if alertas else 0
        score -= 1 if energia_mAh_dia > 50 else 0
        return score, {"ok_bw": ok_bw, "bw_need": bw_need}

    perf = perfil_protocolo(proto)
    sc, meta = score_sistema(perf["bw"], perf["lat"], perf["mAh"], n_sens, alertas)

    st.write(f"**Protocolo**: {proto} | **BW disp.** {perf['bw']} kbps | **Lat.** {perf['lat']} ms | **Consumo** {perf['mAh']} mAh/día")
    st.write(f"**Sensores**: {n_sens} → **BW requerido** ~{meta['bw_need']} kbps | **OK_BW**: {meta['ok_bw']}")
    st.success(f"Score (heurístico): {sc}")

    fig2, ax2 = plt.subplots()
    ax2.bar(["BW requerido","BW disponible"], [meta['bw_need'], perf['bw']])
    ax2.set_title("Ancho de banda: requerido vs disponible")
    ax2.set_ylabel("kbps")
    st.pyplot(fig2)

# ---------- Caso ----------
with tab3:
    st.subheader("Caso: Blockchain en la Fábrica Conectada")
    st.markdown("""
**Entregables del alumno**

- **Sesión 1**: ejecutar con *Tampering ON* + *HMAC* → capturar pantalla con nº de fallos y añadir **3 líneas de reflexión**.
- **Sesión 2**: elegir un protocolo → capturar el bar chart y justificar en **3 líneas** el trade-off latencia/energía.

📄 Documento del caso: si está disponible, revisa `docs/caso.pdf`.  
Si no, usa este espacio como referencia placeholder.
""")
