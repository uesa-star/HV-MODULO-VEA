#!/usr/bin/env python3
"""Descarga el Excel VEA privado de Drive y reemplaza sus tablas en Supabase.

Las credenciales se leen exclusivamente desde variables de entorno de GitHub Actions.

Regla operativa:
- Obligatorias: EDAS, IRAS, FEBRILES, INDIVIDUAL, SOAT.
- Opcionales: VIH, TBC. Si no existen en el Master, no bloquean la carga ni se altera
  el contenido existente de esas tablas en Supabase.
"""
from __future__ import annotations

import io
import json
import os
import re
import sys
import tempfile
import unicodedata
from datetime import date, datetime, time
from typing import Any

import requests
from google.oauth2 import service_account
from googleapiclient.discovery import build
from googleapiclient.http import MediaIoBaseDownload
from openpyxl import load_workbook

REQUIRED_SHEETS = {
    "EDAS": "edas",
    "IRAS": "iras",
    "FEBRILES": "febriles",
    "INDIVIDUAL": "individual",
    "SOAT": "soat",
}

OPTIONAL_SHEETS = {
    "VIH": "vih",
    "TBC": "tbc",
}

BATCH = 500
DELETE_RANGE = 5000


def required(name: str) -> str:
    value = os.environ.get(name, "").strip()
    if not value:
        raise RuntimeError(f"Falta la variable/secreto {name}")
    return value


def column_name(value: Any, index: int) -> str:
    text = unicodedata.normalize("NFKD", str(value or "")).encode("ascii", "ignore").decode()
    text = re.sub(r"[^a-zA-Z0-9]+", "_", text.strip()).strip("_").lower()
    return text or f"columna_{index + 1}"


def json_value(value: Any) -> Any:
    if value is None:
        return None
    if isinstance(value, (datetime, date, time)):
        return value.isoformat()
    if isinstance(value, float) and value != value:
        return None
    if isinstance(value, (str, int, float, bool)):
        return value
    return str(value)


def read_sheet(ws: Any) -> list[dict[str, Any]]:
    rows = ws.iter_rows(values_only=True)
    try:
        headers = next(rows)
    except StopIteration:
        return []
    names: list[str] = []
    used: dict[str, int] = {}
    for i, header in enumerate(headers):
        name = column_name(header, i)
        used[name] = used.get(name, 0) + 1
        names.append(name if used[name] == 1 else f"{name}_{used[name]}")
    output = []
    for row in rows:
        if not any(value not in (None, "") for value in row):
            continue
        output.append({name: json_value(row[i] if i < len(row) else None) for i, name in enumerate(names)})
    return output


def drive_download(file_id: str, credentials_json: str) -> bytes:
    info = json.loads(credentials_json)
    credentials = service_account.Credentials.from_service_account_info(
        info, scopes=["https://www.googleapis.com/auth/drive.readonly"]
    )
    service = build("drive", "v3", credentials=credentials, cache_discovery=False)
    metadata = service.files().get(fileId=file_id, fields="name,mimeType,size").execute()
    mime = metadata.get("mimeType", "")
    name = metadata.get("name", file_id)
    if mime == "application/vnd.google-apps.spreadsheet":
        request = service.files().export_media(
            fileId=file_id,
            mimeType="application/vnd.openxmlformats-officedocument.spreadsheetml.sheet",
        )
    else:
        request = service.files().get_media(fileId=file_id)
    buffer = io.BytesIO()
    downloader = MediaIoBaseDownload(buffer, request)
    done = False
    while not done:
        _, done = downloader.next_chunk()
    raw = buffer.getvalue()
    if not raw.startswith(b"PK"):
        preview = raw[:120].decode("utf-8", errors="replace").replace("\\n", " ")
        raise RuntimeError(
            f"Drive no entregó un XLSX válido para {name} (mime={mime}). "
            f"Respuesta inicial: {preview}"
        )
    print(f"Archivo Drive: {name} ({mime}), {len(raw)} bytes")
    return raw


def supabase_request(base: str, key: str, method: str, table: str, **kwargs: Any) -> requests.Response:
    headers = {
        "apikey": key,
        "Authorization": f"Bearer {key}",
        "Content-Type": "application/json",
    }
    extra_headers = kwargs.pop("headers", None)
    if extra_headers:
        headers.update(extra_headers)
    return requests.request(method, f"{base}/rest/v1/{table}", headers=headers, timeout=120, **kwargs)


def count_table(base: str, key: str, table: str) -> int:
    response = supabase_request(
        base,
        key,
        "GET",
        table,
        headers={
            "apikey": key,
            "Authorization": f"Bearer {key}",
            "Prefer": "count=exact",
            "Range": "0-0",
        },
        params={"select": "_row_id"},
    )
    if response.status_code >= 300:
        raise RuntimeError(
            f"{table}: no se pudo contar la tabla ({response.status_code}): {response.text[:500]}"
        )
    content_range = response.headers.get("content-range", "")
    match = re.search(r"/(\d+)$", content_range)
    if not match:
        raise RuntimeError(f"{table}: Content-Range inválido al contar: {content_range!r}")
    return int(match.group(1))


def row_id_bound(base: str, key: str, table: str, descending: bool) -> int | None:
    response = supabase_request(
        base,
        key,
        "GET",
        table,
        params={
            "select": "_row_id",
            "order": f"_row_id.{'desc' if descending else 'asc'}",
            "limit": "1",
        },
    )
    if response.status_code >= 300:
        raise RuntimeError(
            f"{table}: no se pudo obtener límite de _row_id ({response.status_code}): {response.text[:500]}"
        )
    data = response.json()
    if not data:
        return None
    value = data[0].get("_row_id")
    return int(value) if value is not None else None


def clear_table_by_ranges(base: str, key: str, table: str) -> None:
    min_id = row_id_bound(base, key, table, False)
    max_id = row_id_bound(base, key, table, True)
    if min_id is None or max_id is None:
        print(f"{table}: tabla ya vacía")
        return

    print(f"{table}: limpiando _row_id {min_id}..{max_id} en bloques de {DELETE_RANGE}")
    start = min_id
    blocks = 0
    while start <= max_id:
        end = start + DELETE_RANGE
        response = supabase_request(
            base,
            key,
            "DELETE",
            table,
            headers={
                "apikey": key,
                "Authorization": f"Bearer {key}",
                "Content-Type": "application/json",
                "Prefer": "return=minimal",
            },
            params=[
                ("_row_id", f"gte.{start}"),
                ("_row_id", f"lt.{end}"),
            ],
        )
        if response.status_code >= 300:
            raise RuntimeError(
                f"{table}: error borrando rango {start}-{end - 1} "
                f"({response.status_code}): {response.text[:1000]}"
            )
        blocks += 1
        if blocks % 20 == 0:
            print(f"{table}: {blocks} bloques eliminados...")
        start = end

    remaining = row_id_bound(base, key, table, False)
    if remaining is not None:
        raise RuntimeError(f"{table}: quedaron filas después de la limpieza por rangos")
    print(f"{table}: limpieza completa en {blocks} bloques")


def replace_table(base: str, key: str, table: str, rows: list[dict[str, Any]]) -> None:
    # Evita COUNT(*) sobre tablas infladas: en SOAT superaba el statement timeout.
    clear_table_by_ranges(base, key, table)

    for start in range(0, len(rows), BATCH):
        payload = rows[start:start + BATCH]
        response = supabase_request(
            base,
            key,
            "POST",
            table,
            headers={
                "apikey": key,
                "Authorization": f"Bearer {key}",
                "Content-Type": "application/json",
                "Prefer": "return=minimal",
            },
            data=json.dumps(payload, ensure_ascii=False),
        )
        if response.status_code >= 300:
            raise RuntimeError(
                f"{table}: error insertando lote ({response.status_code}): {response.text[:1000]}"
            )

    final_count = count_table(base, key, table)
    if final_count != len(rows):
        raise RuntimeError(
            f"{table}: verificación final incorrecta; Master={len(rows)} Supabase={final_count}"
        )

    print(f"{table}: reemplazo OK, {final_count} filas exactas")


def main() -> int:
    file_id = required("GOOGLE_DRIVE_FILE_ID")
    base = required("SUPABASE_URL").rstrip("/")
    key = required("SUPABASE_SERVICE_ROLE_KEY")
    raw = drive_download(file_id, required("GOOGLE_SERVICE_ACCOUNT_JSON"))

    with tempfile.NamedTemporaryFile(suffix=".xlsx") as temp:
        temp.write(raw)
        temp.flush()
        workbook = load_workbook(temp.name, read_only=True, data_only=True)
        sheetnames = set(workbook.sheetnames)
        parsed: dict[str, list[dict[str, Any]]] = {}

        missing_required = [sheet for sheet in REQUIRED_SHEETS if sheet not in sheetnames]
        if missing_required:
            raise RuntimeError(
                "Faltan hojas obligatorias del Master VEA: " + ", ".join(missing_required)
            )

        for sheet, table in REQUIRED_SHEETS.items():
            parsed[table] = read_sheet(workbook[sheet])

        optional_present = []
        optional_missing = []
        for sheet, table in OPTIONAL_SHEETS.items():
            if sheet in sheetnames:
                parsed[table] = read_sheet(workbook[sheet])
                optional_present.append(sheet)
            else:
                optional_missing.append(sheet)

        workbook.close()

    print(
        "Excel descargado y validado:",
        ", ".join(f"{k}={len(v)}" for k, v in parsed.items()),
    )
    if optional_present:
        print("Hojas opcionales presentes:", ", ".join(optional_present))
    if optional_missing:
        print(
            "Hojas opcionales ausentes (no bloquean y no se modifican en Supabase):",
            ", ".join(optional_missing),
        )

    for table, rows in parsed.items():
        replace_table(base, key, table, rows)

    print("Sincronización VEA completada correctamente.")
    return 0


if __name__ == "__main__":
    try:
        raise SystemExit(main())
    except Exception as exc:
        print(f"ERROR: {exc}", file=sys.stderr)
        raise
