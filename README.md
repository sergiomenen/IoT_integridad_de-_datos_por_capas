# Mini-Lab IoT: Integridad de datos & Capas

Aplicación interactiva en **Streamlit** que permite:
1. Simular un sensor de temperatura → canal de red con pérdida/manipulación → verificación de integridad (SHA256 vs HMAC).
2. Explorar decisiones en un sistema IoT con tres capas (Percepción, Red, Aplicación) y visualizar trade-offs de ancho de banda, latencia y consumo.

---

## 🚀 Despliegue en Streamlit Cloud (sin CLI)

1. Crea un repositorio en GitHub con:
   - `app.py`
   - `requirements.txt`
   - `README.md`
   - (opcional) `docs/caso.pdf`

2. Ve a [share.streamlit.io](https://iot-integridad-lab.streamlit.app/) → **New app** → conecta tu GitHub → selecciona el repo y rama.

3. Configuración:
   - **Main file**: `app.py`
   - Python 3.11/3.12

4. (Opcional) Añade un secreto para clave fija HMAC:
   - En la app, ve a **App settings → Secrets**.
   - Añade:
     ```
     HMAC_SECRET="cambia-esta-clave"
     ```

5. Deploy. Cada push a `main` redepliega automáticamente.

---

## ✅ Checklist de verificación

- **Sesión 1**: con *Tampering ON + HMAC* aparecen puntos rojos en el gráfico y aumenta el contador de fallos.
- **Sesión 2**: el bar chart responde al nº de sensores y protocolo; el score cambia según latencia/energía.

---

## 📝 Notas docentes

- Un hash simple (SHA256) puede ser recalculado por un atacante que manipula datos.
- HMAC requiere clave secreta compartida → protege integridad contra manipulación sin clave.
- Este concepto conecta con **blockchain/trazabilidad**: registros inmutables + verificación distribuida.

---

## 🔎 Prueba rápida

1. Abre la app en Streamlit Cloud.
2. Ve a **Sesión 1**, selecciona *Tampering = Manipulado* y *Integridad = HMAC*, pulsa **Ejecutar simulación**.
3. Observa puntos rojos (fallos de integridad).
4. Ve a **Sesión 2**, cambia protocolo de *WiFi* a *LoRaWAN* y observa cómo cambia el score y el gráfico.
