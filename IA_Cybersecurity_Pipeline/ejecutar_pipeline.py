"""
ejecutar_pipeline.py
====================
Ejecuta los 8 notebooks del Pipeline de Ciberseguridad con IA en orden,
guarda los resultados ejecutados en la carpeta 'resultados_ejecucion/' y
muestra un resumen final con el estado de cada notebook.

Uso:
    python ejecutar_pipeline.py              # ejecuta todos
    python ejecutar_pipeline.py --nb 02 03  # ejecuta solo los indicados
    python ejecutar_pipeline.py --timeout 600  # timeout por celda en segundos
"""

import os
import sys
import time
import argparse
import traceback
from pathlib import Path
from datetime import datetime

# ── Dependencias ────────────────────────────────────────────────────────────
try:
    import nbformat
    from nbconvert.preprocessors import ExecutePreprocessor, CellExecutionError
except ImportError:
    print("[ERROR] Faltan dependencias. Ejecuta:")
    print("        pip install nbformat nbconvert ipykernel")
    sys.exit(1)

# ── Configuración ────────────────────────────────────────────────────────────
PIPELINE_DIR   = Path(__file__).parent          # carpeta de este script
RESULTS_DIR    = PIPELINE_DIR / "resultados_ejecucion"
KERNEL_NAME    = "python3"

NOTEBOOKS = [
    "01_entorno_setup.ipynb",
    "02_deteccion_amenazas.ipynb",
    "03_deteccion_malware.ipynb",
    "04_respuesta_incidentes.ipynb",
    "05_analisis_comportamiento.ipynb",
    "06_explicabilidad_xai.ipynb",
    "07_ataques_adversariales.ipynb",
    "08_pipeline_integrado.ipynb",
]

# ── Helpers ──────────────────────────────────────────────────────────────────
def banner(text: str, char: str = "=", width: int = 65) -> None:
    print("\n" + char * width)
    print(f"  {text}")
    print(char * width)


def fmt_time(seconds: float) -> str:
    if seconds < 60:
        return f"{seconds:.1f}s"
    m, s = divmod(int(seconds), 60)
    return f"{m}m {s:02d}s"


def run_notebook(nb_path: Path, results_dir: Path, timeout: int) -> dict:
    """
    Ejecuta un notebook y guarda la versión ejecutada en results_dir.
    Devuelve un dict con estado, tiempo y mensaje de error si aplica.
    """
    result = {
        "notebook": nb_path.name,
        "status":   "OK",
        "elapsed":  0.0,
        "error":    None,
        "output":   None,
    }

    # Nombre del archivo de salida
    stem = nb_path.stem.replace(".ipynb", "")
    out_name = stem + "_ejecutado.ipynb"
    out_path = results_dir / out_name
    result["output"] = out_path

    print(f"\n  Leyendo: {nb_path.name}")
    with open(nb_path, encoding="utf-8") as f:
        nb = nbformat.read(f, as_version=4)

    ep = ExecutePreprocessor(
        timeout=timeout,
        kernel_name=KERNEL_NAME,
        allow_errors=False,          # detener en primer error de celda
    )

    t0 = time.time()
    try:
        # resources['metadata']['path'] fija el cwd del kernel al directorio
        # del notebook, para que los paths relativos (data/, models/) funcionen
        ep.preprocess(nb, {"metadata": {"path": str(PIPELINE_DIR)}})
        result["elapsed"] = time.time() - t0
        print(f"  ✓ Completado en {fmt_time(result['elapsed'])}")

    except CellExecutionError as exc:
        result["elapsed"] = time.time() - t0
        result["status"]  = "ERROR"
        result["error"]   = str(exc)[:500]
        print(f"  ✗ Error en celda ({fmt_time(result['elapsed'])})")
        print(f"    {result['error'][:200]}")

    except Exception as exc:
        result["elapsed"] = time.time() - t0
        result["status"]  = "ERROR"
        result["error"]   = traceback.format_exc()[:500]
        print(f"  ✗ Error inesperado: {exc}")

    # Guardar notebook ejecutado (incluso si hubo error, para inspección)
    results_dir.mkdir(parents=True, exist_ok=True)
    with open(out_path, "w", encoding="utf-8") as f:
        nbformat.write(nb, f)
    print(f"  → Guardado: resultados_ejecucion/{out_name}")

    return result


def print_summary(results: list, total_time: float) -> None:
    banner("RESUMEN DE EJECUCIÓN")
    ok_count  = sum(1 for r in results if r["status"] == "OK")
    err_count = sum(1 for r in results if r["status"] == "ERROR")
    skip_count = sum(1 for r in results if r["status"] == "SKIP")

    print(f"\n  {'Notebook':<40} {'Estado':>8}  {'Tiempo':>8}")
    print("  " + "-" * 60)
    for r in results:
        icon  = "✓" if r["status"] == "OK" else ("⚠" if r["status"] == "SKIP" else "✗")
        color = ""
        print(f"  {icon} {r['notebook']:<38} {r['status']:>8}  {fmt_time(r['elapsed']):>8}")
        if r["error"]:
            # Mostrar primera línea del error
            first_line = r["error"].split("\n")[0][:70]
            print(f"      └─ {first_line}")

    print("  " + "-" * 60)
    print(f"  Total: {ok_count} OK  |  {err_count} errores  |  {skip_count} omitidos")
    print(f"  Tiempo total: {fmt_time(total_time)}")

    if ok_count == len(results):
        print("\n  🎉 ¡Pipeline ejecutado completamente!")
        print(f"  Los notebooks ejecutados están en: resultados_ejecucion/")
    elif err_count > 0:
        print("\n  ⚠  Algunos notebooks fallaron.")
        print("  Revisa los archivos en resultados_ejecucion/ para ver el detalle.")


# ── Main ─────────────────────────────────────────────────────────────────────
def main():
    parser = argparse.ArgumentParser(
        description="Ejecuta los notebooks del Pipeline de Ciberseguridad con IA"
    )
    parser.add_argument(
        "--nb",
        nargs="+",
        metavar="N",
        help="Números de notebooks a ejecutar (ej: --nb 02 03 04). "
             "Por defecto ejecuta todos.",
    )
    parser.add_argument(
        "--timeout",
        type=int,
        default=300,
        help="Timeout por celda en segundos (default: 300)",
    )
    parser.add_argument(
        "--skip-errors",
        action="store_true",
        help="Continuar con el siguiente notebook si uno falla",
    )
    args = parser.parse_args()

    # Filtrar notebooks si se especificaron
    if args.nb:
        selected = set(args.nb)
        notebooks_to_run = [
            nb for nb in NOTEBOOKS
            if any(nb.startswith(n) for n in selected)
        ]
        if not notebooks_to_run:
            print(f"[ERROR] No se encontraron notebooks con los números: {args.nb}")
            sys.exit(1)
    else:
        notebooks_to_run = NOTEBOOKS

    banner(
        f"Pipeline de Ciberseguridad con IA\n"
        f"  Fecha: {datetime.now().strftime('%Y-%m-%d %H:%M:%S')}\n"
        f"  Notebooks: {len(notebooks_to_run)}  |  Timeout/celda: {args.timeout}s\n"
        f"  Directorio: {PIPELINE_DIR}"
    )

    print("\n  NOTA: Los gráficos se guardan dentro de los notebooks ejecutados.")
    print("        Ábrelos en Jupyter o VS Code para verlos.")
    print("        Los archivos de datos y modelos se generan en data/ y models/")

    results   = []
    total_t0  = time.time()
    stop_exec = False

    for nb_name in notebooks_to_run:
        nb_path = PIPELINE_DIR / nb_name

        if not nb_path.exists():
            print(f"\n  [SKIP] No encontrado: {nb_name}")
            results.append({
                "notebook": nb_name,
                "status":   "SKIP",
                "elapsed":  0.0,
                "error":    "Archivo no encontrado",
                "output":   None,
            })
            continue

        if stop_exec:
            results.append({
                "notebook": nb_name,
                "status":   "SKIP",
                "elapsed":  0.0,
                "error":    "Omitido por error previo",
                "output":   None,
            })
            continue

        banner(f"Ejecutando: {nb_name}", char="-", width=65)
        result = run_notebook(nb_path, RESULTS_DIR, args.timeout)
        results.append(result)

        if result["status"] == "ERROR" and not args.skip_errors:
            print("\n  [!] Deteniendo ejecución por error.")
            print("      Usa --skip-errors para continuar con el siguiente notebook.")
            stop_exec = True

    total_time = time.time() - total_t0
    print_summary(results, total_time)


if __name__ == "__main__":
    main()
