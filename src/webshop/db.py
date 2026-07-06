"""SQLite database setup, schema, and seed data."""

from __future__ import annotations

import sqlite3
from pathlib import Path

DEFAULT_DB_PATH = Path(__file__).resolve().parents[2] / "data" / "webshop.db"

SCHEMA = """
CREATE TABLE IF NOT EXISTS products (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    name TEXT NOT NULL,
    description TEXT NOT NULL,
    price REAL NOT NULL,
    category TEXT NOT NULL
);

CREATE TABLE IF NOT EXISTS users (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    email TEXT NOT NULL UNIQUE,
    password_hash TEXT NOT NULL
);

CREATE TABLE IF NOT EXISTS orders (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    user_id INTEGER NOT NULL,
    product_id INTEGER NOT NULL,
    quantity INTEGER NOT NULL,
    status TEXT NOT NULL,
    FOREIGN KEY (user_id) REFERENCES users (id),
    FOREIGN KEY (product_id) REFERENCES products (id)
);
"""

SEED_PRODUCTS = [
    ("Wireless Headphones", "Noise-cancelling over-ear headphones", 149.99, "electronics"),
    ("USB-C Hub", "7-in-1 adapter with HDMI and ethernet", 59.99, "electronics"),
    ("Mechanical Keyboard", "Hot-swappable switches, RGB backlight", 129.99, "electronics"),
    ("27-inch Monitor", "4K IPS display with USB-C power delivery", 399.99, "electronics"),
    ("Laptop Stand", "Aluminum adjustable stand", 49.99, "electronics"),
    ("Denim Jacket", "Classic blue denim, medium wash", 79.99, "clothing"),
    ("Running Shoes", "Lightweight trainers for road running", 119.99, "clothing"),
    ("Cotton T-Shirt", "Organic cotton crew neck", 24.99, "clothing"),
    ("Winter Scarf", "Wool blend, charcoal grey", 34.99, "clothing"),
    ("Leather Belt", "Full-grain leather, brown", 44.99, "clothing"),
]

SEED_USERS = [
    ("alice@example.com", "5d41402abc4b2a76b9719d911017c592"),  # "hello" md5
    ("bob@example.com", "098f6bcd4621d373cade4e832627b4f6"),  # "test" md5
    ("carol@example.com", "5f4dcc3b5aa765d61d8327deb882cf99"),  # "password" md5
]

SEED_ORDERS = [
    (1, 1, 1, "shipped"),
    (1, 3, 2, "processing"),
    (2, 6, 1, "delivered"),
    (3, 2, 1, "shipped"),
    (3, 8, 3, "pending"),
]


def get_db_path() -> Path:
    return DEFAULT_DB_PATH


def get_connection(db_path: Path | None = None) -> sqlite3.Connection:
    path = db_path or get_db_path()
    path.parent.mkdir(parents=True, exist_ok=True)
    conn = sqlite3.connect(path)
    conn.row_factory = sqlite3.Row
    return conn


def init_db(db_path: Path | None = None) -> None:
    path = db_path or get_db_path()
    path.parent.mkdir(parents=True, exist_ok=True)

    with get_connection(path) as conn:
        conn.executescript(SCHEMA)

        product_count = conn.execute("SELECT COUNT(*) FROM products").fetchone()[0]
        if product_count == 0:
            conn.executemany(
                "INSERT INTO products (name, description, price, category) VALUES (?, ?, ?, ?)",
                SEED_PRODUCTS,
            )

        user_count = conn.execute("SELECT COUNT(*) FROM users").fetchone()[0]
        if user_count == 0:
            conn.executemany(
                "INSERT INTO users (email, password_hash) VALUES (?, ?)",
                SEED_USERS,
            )

        order_count = conn.execute("SELECT COUNT(*) FROM orders").fetchone()[0]
        if order_count == 0:
            conn.executemany(
                "INSERT INTO orders (user_id, product_id, quantity, status) VALUES (?, ?, ?, ?)",
                SEED_ORDERS,
            )

        conn.commit()
