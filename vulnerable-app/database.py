"""SQLite database setup for vulnerable web application."""

import sqlite3
import os

# Store database in /app/data for volume persistence
DATA_DIR = '/app/data'
DATABASE_PATH = os.path.join(DATA_DIR, 'vulnerable.db')

# Ensure the data directory exists
os.makedirs(DATA_DIR, exist_ok=True)


def get_db_connection():
    """Get a connection to the SQLite database."""
    conn = sqlite3.connect(DATABASE_PATH)
    conn.row_factory = sqlite3.Row
    return conn


def init_db():
    """Initialize the database with tables and seed data."""
    conn = get_db_connection()
    cursor = conn.cursor()
    
    # Create users table
    cursor.execute('''
        CREATE TABLE IF NOT EXISTS users (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            username TEXT NOT NULL UNIQUE,
            password TEXT NOT NULL,
            email TEXT,
            role TEXT DEFAULT 'user'
        )
    ''')
    
    # Create products table
    cursor.execute('''
        CREATE TABLE IF NOT EXISTS products (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            name TEXT NOT NULL,
            description TEXT,
            price REAL
        )
    ''')
    
    # Create comments table for stored XSS
    cursor.execute('''
        CREATE TABLE IF NOT EXISTS comments (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            content TEXT NOT NULL,
            created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP
        )
    ''')
    
    # Seed users (plaintext passwords for demo)
    users = [
        ('admin', 'password', 'admin@example.com', 'admin'),
        ('user', 'user123', 'user@example.com', 'user'),
        ('guest', 'guest', 'guest@example.com', 'guest'),
        ('test', 'test123', 'test@example.com', 'user'),
    ]
    
    for username, password, email, role in users:
        try:
            cursor.execute(
                'INSERT INTO users (username, password, email, role) VALUES (?, ?, ?, ?)',
                (username, password, email, role)
            )
        except sqlite3.IntegrityError:
            pass  # User already exists
    
    # Seed products
    products = [
        ('Laptop Pro', 'High-performance laptop with 16GB RAM', 1299.99),
        ('Wireless Mouse', 'Ergonomic wireless mouse', 29.99),
        ('USB-C Hub', '7-in-1 USB-C hub with HDMI', 49.99),
        ('Mechanical Keyboard', 'RGB mechanical keyboard', 89.99),
        ('Monitor 27"', '4K IPS monitor with HDR', 399.99),
        ('Webcam HD', '1080p webcam with microphone', 79.99),
        ('Headphones', 'Noise-cancelling wireless headphones', 199.99),
        ('SSD 1TB', 'NVMe SSD with 3500MB/s read', 129.99),
    ]
    
    for name, description, price in products:
        cursor.execute(
            'INSERT OR IGNORE INTO products (name, description, price) VALUES (?, ?, ?)',
            (name, description, price)
        )
    
    conn.commit()
    conn.close()


def reset_db():
    """Reset the database to initial state."""
    if os.path.exists(DATABASE_PATH):
        os.remove(DATABASE_PATH)
    init_db()


if __name__ == '__main__':
    init_db()
    print(f"Database initialized at {DATABASE_PATH}")

