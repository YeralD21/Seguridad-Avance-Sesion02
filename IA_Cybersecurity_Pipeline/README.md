# Pipeline de Ciberseguridad con IA - Guía Técnica

## Descripción
Sistema integrado de detección de anomalías, clasificación de malware y triaje automático. Este proyecto utiliza técnicas avanzadas de Inteligencia Artificial para fortalecer las capacidades de respuesta y análisis en entornos de ciberseguridad.

## Flujo de Trabajo
Los notebooks en este proyecto están diseñados para ejecutarse de forma secuencial, del **01 al 08**. Es fundamental seguir este orden, ya que cada etapa genera dependencias críticas (como modelos entrenados en formato `.pkl` o conjuntos de datos procesados en `.csv`) que son requeridas por el siguiente paso del pipeline.

1. **01_entorno_setup**: Configuración de dependencias y validación del ambiente.
2. **02_deteccion_amenazas**: Modelado de detección de intrusiones y anomalías.
3. **03_deteccion_malware**: Clasificación de archivos maliciosos mediante análisis estático/dinámico.
4. **04_respuesta_incidentes**: Automatización del triaje y priorización de alertas.
5. **05_analisis_comportamiento**: Detección de comportamientos sospechosos (UBA).
6. **06_explicabilidad_xai**: Interpretación de las decisiones de los modelos (SHAP/LIME).
7. **07_ataques_adversariales**: Evaluación de robustez ante ataques dirigidos a la IA.
8. **08_pipeline_integrado**: Orquestación final del sistema completo.
