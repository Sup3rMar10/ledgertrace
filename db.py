"""SQLite helpers shared by the API, analysis and sim.py."""
import os
import sqlite3
from contextlib import contextmanager
from datetime import datetime, timezone

DB_PATH = os.environ.get("LT_DB", os.path.join(os.path.dirname(os.path.abspath(__file__)), "ledgertrace.db"))

SCHEMA = """
CREATE TABLE IF NOT EXISTS users(
  id INTEGER PRIMARY KEY, username TEXT UNIQUE NOT NULL, pw_hash TEXT NOT NULL, created_at TEXT NOT NULL);
CREATE TABLE IF NOT EXISTS sessions(
  token_hash TEXT PRIMARY KEY, user_id INTEGER NOT NULL REFERENCES users(id) ON DELETE CASCADE,
  csrf TEXT NOT NULL, expires_at INTEGER NOT NULL);
CREATE TABLE IF NOT EXISTS txs(txid TEXT PRIMARY KEY, seq INTEGER UNIQUE NOT NULL, height INTEGER NOT NULL, ts TEXT NOT NULL);
CREATE TABLE IF NOT EXISTS inputs(
  txid TEXT NOT NULL REFERENCES txs(txid), n INTEGER NOT NULL, prev_txid TEXT NOT NULL, prev_n INTEGER NOT NULL,
  PRIMARY KEY(txid, n));
CREATE TABLE IF NOT EXISTS outputs(
  txid TEXT NOT NULL REFERENCES txs(txid), n INTEGER NOT NULL, address TEXT NOT NULL, value INTEGER NOT NULL,
  spent_by TEXT, PRIMARY KEY(txid, n));
CREATE TABLE IF NOT EXISTS addresses(address TEXT PRIMARY KEY, label TEXT NOT NULL, kind TEXT NOT NULL);
CREATE TABLE IF NOT EXISTS flags(txid TEXT PRIMARY KEY REFERENCES txs(txid), kind TEXT NOT NULL, note TEXT NOT NULL);
CREATE TABLE IF NOT EXISTS clusters(address TEXT PRIMARY KEY, cluster INTEGER NOT NULL);
CREATE TABLE IF NOT EXISTS patterns(
  id INTEGER PRIMARY KEY, kind TEXT NOT NULL, txid TEXT NOT NULL, size INTEGER NOT NULL, detail TEXT NOT NULL);
CREATE TABLE IF NOT EXISTS risk_scores(
  address TEXT PRIMARY KEY, score INTEGER NOT NULL, reasons TEXT NOT NULL, updated_at TEXT NOT NULL);
CREATE TABLE IF NOT EXISTS cases(
  id INTEGER PRIMARY KEY, user_id INTEGER NOT NULL REFERENCES users(id) ON DELETE CASCADE,
  name TEXT NOT NULL, seed_txid TEXT NOT NULL, seed_vout INTEGER NOT NULL,
  method TEXT NOT NULL CHECK(method IN ('poison','haircut','fifo')), max_hops INTEGER NOT NULL,
  created_at TEXT NOT NULL, summary TEXT NOT NULL, graph TEXT NOT NULL);
CREATE TABLE IF NOT EXISTS case_hits(
  id INTEGER PRIMARY KEY, case_id INTEGER NOT NULL REFERENCES cases(id) ON DELETE CASCADE,
  address TEXT NOT NULL, txid TEXT NOT NULL, hops INTEGER NOT NULL, taint INTEGER NOT NULL,
  kind TEXT NOT NULL, label TEXT NOT NULL);
CREATE INDEX IF NOT EXISTS idx_inputs_prev ON inputs(prev_txid, prev_n);
CREATE INDEX IF NOT EXISTS idx_outputs_addr ON outputs(address);
CREATE INDEX IF NOT EXISTS idx_hits_case ON case_hits(case_id);
"""


def now():
    return datetime.now(timezone.utc).isoformat(timespec="seconds")


@contextmanager
def conn():
    c = sqlite3.connect(DB_PATH)
    c.row_factory = sqlite3.Row
    c.execute("PRAGMA foreign_keys = ON")
    try:
        yield c
        c.commit()
    finally:
        c.close()


def init():
    with conn() as c:
        c.executescript(SCHEMA)
