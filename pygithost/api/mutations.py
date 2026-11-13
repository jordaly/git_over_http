"""Durable idempotency claims, audit metadata and cached resource responses."""

import hashlib
import json

from .. import database
from .errors import APIError


def claim(user_id, key, fingerprint, request_id, method, path):
    key_hash = hashlib.sha256(key.encode()).hexdigest()
    conn = database._db_connect()
    try:
        conn.execute("BEGIN IMMEDIATE")
        row = conn.execute(
            "SELECT fingerprint,state,status,response_json FROM api_mutations WHERE user_id=? AND key_hash=?",
            (user_id, key_hash)).fetchone()
        if row:
            if row[0] != fingerprint:
                raise APIError(409, "idempotency_conflict", "Idempotency key was used for a different request.")
            if row[1] != "completed":
                raise APIError(409, "operation_pending",
                               "The previous operation is pending or its outcome is uncertain. Inspect the resource before retrying.")
            conn.commit()
            return key_hash, (row[2], json.loads(row[3]))
        conn.execute(
            "INSERT INTO api_mutations(user_id,key_hash,fingerprint,request_id,method,path) VALUES(?,?,?,?,?,?)",
            (user_id, key_hash, fingerprint, request_id, method, path))
        conn.commit()
        return key_hash, None
    finally:
        conn.close()


def complete(user_id, key_hash, status, payload):
    conn = database._db_connect()
    try:
        conn.execute(
            "UPDATE api_mutations SET state='completed',status=?,response_json=?,"
            "finished_at=strftime('%Y-%m-%dT%H:%M:%SZ','now') WHERE user_id=? AND key_hash=?",
            (status, json.dumps(payload, ensure_ascii=True, allow_nan=False), user_id, key_hash))
    finally:
        conn.close()
