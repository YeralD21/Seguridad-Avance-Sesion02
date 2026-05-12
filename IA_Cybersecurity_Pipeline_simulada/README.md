# Pipeline de Ciberseguridad con IA - Versión Simulada

## Descripción
Esta carpeta contiene el **entorno de prueba** del sistema integrado de detección de anomalías, clasificación de malware y triaje automático. Todos los datasets son **sintéticos y autogenerados**, permitiendo ejecutar el pipeline completo sin necesidad de datos reales.

## Diferencia con la carpeta principal
| Carpeta | Dataset | Uso |
| :--- | :--- | :--- |
| `IA_Cybersecurity_Pipeline/` | `data/network_traffic.csv` (datos **reales**) | Producción |
| `IA_Cybersecurity_Pipeline_simulada/` | `data/network_traffic.csv` (datos **simulados**) | Pruebas y desarrollo |

## Datasets simulados disponibles
| Archivo | Registros | Descripción |
| :--- | :--- | :--- |
| `data/network_traffic.csv` | 5,250 | Tráfico de red (5,000 normal + 250 anómalo) |
| `data/file_features.csv` | 1,000 | Características PE (800 benign + 200 malicious) |
| `data/incident_data.csv` | 2,000 | Incidentes de seguridad por severidad |
| `data/user_activity_logs.csv` | 1,035 | Logs de actividad de 5 usuarios |

## Flujo de Trabajo
Los notebooks deben ejecutarse en orden del **01 al 08**. En esta versión simulada, **cada notebook genera automáticamente los datos que necesita**, por lo que pueden ejecutarse de forma independiente.

1. **01_entorno_setup** → Validación de entorno y creación de carpetas.
2. **02_deteccion_amenazas** → Isolation Forest + Autoencoder sobre tráfico simulado.
3. **03_deteccion_malware** → Decision Tree + Random Forest sobre features PE simulados.
4. **04_respuesta_incidentes** → SVM de triaje sobre incidentes simulados.
5. **05_analisis_comportamiento** → UBA sobre logs de usuario simulados.
6. **06_explicabilidad_xai** → SHAP sobre el modelo de malware.
7. **07_ataques_adversariales** → Ruido adversarial y entrenamiento robusto.
8. **08_pipeline_integrado** → Orquestación completa + detección de deriva.

## Regenerar datos simulados
```bash
python generar_data_simulada.py
```
