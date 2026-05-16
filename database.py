import sqlite3


DB_NAME = "threat_cases.db"


def initialize_database():

    conn = sqlite3.connect(DB_NAME)

    cursor = conn.cursor()

    cursor.execute("""
CREATE TABLE IF NOT EXISTS investigations (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    user TEXT,
    alert_type TEXT,
    risk_score REAL,
    notes TEXT,
    status TEXT,
    assigned_to TEXT,
    created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP
)
""")

    conn.commit()

    conn.close()


def save_case(
    user,
    alert_type,
    risk_score,
    notes,
    status,
    assigned_to
):
    conn = sqlite3.connect(DB_NAME)

    cursor = conn.cursor()

    cursor.execute("""
        INSERT INTO investigations (
            user,
            alert_type,
            risk_score,
            notes,
            status,
            assigned_to
        )
        VALUES (?, ?, ?, ?, ?, ?)
    """, (
        user,
        alert_type,
        risk_score,
        notes,
        status,
        assigned_to
    ))

    conn.commit()
    conn.close()


def load_cases():

    conn = sqlite3.connect(DB_NAME)

    cursor = conn.cursor()

    cursor.execute("""
        SELECT
            id,
            user,
            alert_type,
            risk_score,
            notes,
            status,
            assigned_to,
            created_at
        FROM investigations
    """)

    rows = cursor.fetchall()

    conn.close()

    return rows