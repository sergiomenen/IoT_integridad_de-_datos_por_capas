# Lab IoT — Integridad & Capas (Streamlit)

Laboratorio web para experimentar con integridad de datos IoT:
- Firma por registro con **HMAC-SHA256** (clave vía **Streamlit Secrets**).
- Simulación de manipulación por capa (percepción, red, aplicación).
- Verificación end-to-end + resumen de incidencias.
- Visualización de series temporales con **matplotlib** (sin seaborn).
- Cálculo opcional de **Merkle Root** sobre el lote firmado.
- Exportación CSV firmado.

## Despliegue (Streamlit Community Cloud)
1. Sube este repo a GitHub.
2. En https://share.streamlit.io/ crea una nueva app, apunta a `app.py`.
3. En *App settings → Secrets*, pega:
   ```toml
   hmac_key = "TU_CLAVE_SECRETA_MUY_LARGA_Y_ALEATORIA"
