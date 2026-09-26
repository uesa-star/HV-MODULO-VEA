#!/usr/bin/env python3
"""Guarda de sincronización VEA: solo publica cuando el archivo de Google Drive cambió.

Si la tabla de control (vea_sync_control) no está disponible (permisos/grants
pendientes), se degrada con fail-open: sincroniza igual para no bloquear el
reflejo de datos y avisa por stderr.
"""
from __future__ import annotations
import hashlib
import io
import json
import os
import sys
from datetime import datetime, timezone

import requests
from google.oauth2 import service_account
from googleapiclient.discovery import build

FILE_ID = os.environ["GOOGLE_DRIVE_FILE_ID"]
BASE = os.environ["SUPABASE_URL"].rstrip("/")
KEY = os.environ["SUPABASE_SERVICE_ROLE_KEY"]
CREDS = os.environ["GOOGLE_SERVICE_ACCOUNT_JSON"]

def sb(method, table, **kwargs):
    headers = {"apikey": KEY, "Authorization": f"Bearer {KEY}", "Content-Type": "application/json"}
    extra = kwargs.pop("headers", {})
    headers.update(extra)
    return requests.request(method, f"{BASE}/rest/v1/{table}", headers=headers, timeout=120, **kwargs)

def drive_service():
    info = json.loads(CREDS)
    creds = service_account.Credentials.from_service_account_info(
        info, scopes=["https://www.googleapis.com/auth/drive.readonly"]
    )
    return build("drive", "v3", credentials=creds, cache_discovery=False)

def leer_control():
    """Fila de control actual o None si la tabla no está disponible (fail-open)."""
    try:
        current = sb("GET", "vea_sync_control", params={
            "select": "source_modified_time,source_sha256,last_status",
            "id": "eq.1",
        })
        current.raise_for_status()
        filas = current.json()
        return filas[0] if filas else {}
    except Exception as exc:
        print(
            f"VEA_SYNC_CONTROL_NO_DISPONIBLE: {exc}; se omite el control de cambios "
            "y se sincroniza de todas formas (fail-open).",
            file=sys.stderr,
        )
        return None

def registrar_control(payload, contexto):
    """Actualiza vea_sync_control sin bloquear el flujo si falla."""
    try:
        update = sb("PATCH", "vea_sync_control", params={"id": "eq.1"}, data=json.dumps(payload))
        update.raise_for_status()
    except Exception as exc:
        print(
            f"VEA_SYNC_CONTROL_{contexto}_NO_REGISTRADO: {exc}",
            file=sys.stderr,
        )

def main():
    service = drive_service()
    meta = service.files().get(fileId=FILE_ID, fields="id,name,mimeType,modifiedTime,size").execute()
    modified = meta.get("modifiedTime")
    if not modified:
        raise RuntimeError("Google Drive no devolvió modifiedTime.")

    row = leer_control()
    if row is not None and row.get("source_modified_time") == modified and row.get("last_status") == "success":
        print(f"VEA_SYNC_SKIP: sin cambios en Google Drive desde {modified}.")
        return 0

    print(f"VEA_SYNC_CHANGE: Drive modificado {modified}; ejecutando sincronización completa.")
    from sync_vea import main as sync_main
    try:
        result = sync_main()
        registrar_control({
            "source_file_id": FILE_ID,
            "source_modified_time": modified,
            "source_sha256": None,
            "last_success_at": datetime.now(timezone.utc).isoformat(),
            "last_status": "success",
            "last_message": f"Sincronización automática OK: {meta.get('name', FILE_ID)}",
            "updated_at": datetime.now(timezone.utc).isoformat(),
        }, "SUCCESS")
        return int(result or 0)
    except Exception as exc:
        registrar_control({
            "source_file_id": FILE_ID,
            "source_modified_time": modified,
            "last_status": "error",
            "last_message": str(exc)[:1000],
            "updated_at": datetime.now(timezone.utc).isoformat(),
        }, "ERROR")
        raise

if __name__ == "__main__":
    try:
        raise SystemExit(main())
    except Exception as exc:
        print(f"ERROR: {exc}", file=sys.stderr)
        raise
