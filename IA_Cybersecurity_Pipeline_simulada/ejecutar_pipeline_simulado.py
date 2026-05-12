"""
ejecutar_pipeline_simulado.py
==============================
Ejecuta automaticamente todos los notebooks del pipeline simulado
en orden del 01 al 08 y guarda los resultados con las salidas incluidas.

Uso:
    python ejecutar_pipeline_simulado.py

Los notebooks ejecutados se guardan en la carpeta 'resultados_ejecucion/'.
"""

import subprocess
import sys
import os
import time
from pathlib import Path

# --- CONFIGURACION -----------------------------------------------
CARPETA_RESULTADOS = "resultados_ejecucion"
TIMEOUT_POR_NOTEBOOK = 300  # segundos maximos por notebook (5 min)

NOTEBOOKS = [
    ("01_entorno_setup.ipynb",           "Cap 2 - Configuracion del Entorno"),
    ("02_deteccion_amenazas.ipynb",      "Cap 3 - Deteccion de Amenazas"),
    ("03_deteccion_malware.ipynb",       "Cap 4 - Deteccion de Malware"),
    ("04_respuesta_incidentes.ipynb",    "Cap 5 - Respuesta a Incidentes"),
    ("05_analisis_comportamiento.ipynb", "Cap 6 - Analisis de Comportamiento (UBA)"),
    ("06_explicabilidad_xai.ipynb",      "Cap 7 - Explicabilidad (XAI)"),
    ("07_ataques_adversariales.ipynb",   "Cap 8 - Ataques Adversariales"),
    ("08_pipeline_integrado.ipynb",      "Cap 9-10 - Pipeline Integrado"),
]


# --- HELPERS -----------------------------------------------------
def linea(titulo=""):
    ancho = 65
    if titulo:
        pad = ancho - len(titulo) - 4
        print(f"\n== {titulo} {'=' * pad}")
    else:
        print("=" * ancho)


def check_jupyter():
    resultado = subprocess.run(
        [sys.executable, "-m", "jupyter", "nbconvert", "--version"],
        capture_output=True, text=True
    )
    if resultado.returncode != 0:
        print("[ERROR] nbconvert no esta instalado.")
        print("        Ejecuta:  pip install jupyter nbconvert ipykernel")
        sys.exit(1)


def ejecutar_notebook(nb_entrada, nb_salida, timeout=TIMEOUT_POR_NOTEBOOK):
    """Ejecuta un notebook. Retorna (exitoso, tiempo, mensaje_error)."""
    cmd = [
        sys.executable, "-m", "jupyter", "nbconvert",
        "--to", "notebook",
        "--execute",
        f"--ExecutePreprocessor.timeout={timeout}",
        "--ExecutePreprocessor.kernel_name=python3",
        f"--output={nb_salida}",
        nb_entrada,
    ]
    inicio = time.time()
    resultado = subprocess.run(cmd, capture_output=True, text=True)
    elapsed = round(time.time() - inicio, 1)

    if resultado.returncode != 0:
        error = resultado.stderr[-800:] if resultado.stderr else "Error desconocido"
        return False, elapsed, error
    return True, elapsed, ""


# --- EJECUCION PRINCIPAL -----------------------------------------
def main():
    linea()
    print("  PIPELINE DE CIBERSEGURIDAD CON IA - EJECUCION AUTOMATICA")
    linea()
    print(f"  Carpeta de resultados : {CARPETA_RESULTADOS}/")
    print(f"  Notebooks a ejecutar  : {len(NOTEBOOKS)}")
    print(f"  Timeout por notebook  : {TIMEOUT_POR_NOTEBOOK}s")
    linea()

    check_jupyter()
    os.makedirs(CARPETA_RESULTADOS, exist_ok=True)

    resultados = []
    total_inicio = time.time()

    for i, (nb_archivo, descripcion) in enumerate(NOTEBOOKS, 1):
        print(f"\n[{i}/{len(NOTEBOOKS)}] {descripcion}")
        print(f"      Archivo : {nb_archivo}")

        if not Path(nb_archivo).exists():
            print(f"      [OMITIDO] Archivo no encontrado")
            resultados.append((nb_archivo, "OMITIDO", 0.0, ""))
            continue

        nombre_salida = nb_archivo.replace(".ipynb", "_ejecutado.ipynb")
        ruta_salida   = os.path.join(CARPETA_RESULTADOS, nombre_salida)

        print(f"      Estado  : ejecutando...", end="", flush=True)
        exitoso, elapsed, error = ejecutar_notebook(nb_archivo, ruta_salida)

        if exitoso:
            size_kb = round(Path(ruta_salida).stat().st_size / 1024, 1)
            print(f" [OK] {elapsed}s | {size_kb} KB")
            resultados.append((nb_archivo, "OK", elapsed, ""))
        else:
            print(f" [ERROR] {elapsed}s")
            lineas = [l for l in error.split("\n") if l.strip() and "WARNING" not in l]
            for ln in lineas[-4:]:
                print(f"         -> {ln}")
            resultados.append((nb_archivo, "ERROR", elapsed, lineas[-1] if lineas else ""))

    # --- RESUMEN --------------------------------------------------
    total_tiempo = round(time.time() - total_inicio, 1)
    n_ok     = sum(1 for _, e, _, _ in resultados if e == "OK")
    n_err    = sum(1 for _, e, _, _ in resultados if e == "ERROR")
    n_omit   = sum(1 for _, e, _, _ in resultados if e == "OMITIDO")

    linea("RESUMEN DE EJECUCION")
    print(f"  [OK]     Exitosos  : {n_ok}/{len(NOTEBOOKS)}")
    print(f"  [ERROR]  Con error : {n_err}/{len(NOTEBOOKS)}")
    print(f"  [--]     Omitidos  : {n_omit}/{len(NOTEBOOKS)}")
    print(f"  Tiempo total       : {total_tiempo}s")
    linea()

    print(f"\n  {'Notebook':<43} {'Estado':<9} {'Tiempo':>7}")
    print(f"  {'-'*43} {'-'*9} {'-'*7}")
    for nb, estado, t, _ in resultados:
        print(f"  {nb:<43} {estado:<9} {t:>6.1f}s")
    linea()

    if n_ok == len(NOTEBOOKS):
        print("\n  [OK] TODOS LOS NOTEBOOKS SE EJECUTARON CORRECTAMENTE!")
    elif n_err > 0:
        print(f"\n  [!!] {n_err} notebook(s) tuvieron errores. Revisa el detalle arriba.")
    else:
        print(f"\n  [--] {n_omit} notebook(s) omitidos por no encontrarse.")

    ruta_abs = os.path.abspath(CARPETA_RESULTADOS)
    print(f"\n  Resultados en: {ruta_abs}")
    print(f"  Abre los archivos *_ejecutado.ipynb en VS Code para ver")
    print(f"  todas las salidas, graficos y resultados generados.\n")


if __name__ == "__main__":
    main()
