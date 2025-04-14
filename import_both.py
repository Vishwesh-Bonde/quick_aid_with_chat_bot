import sqlite3
import re
from docx import Document

# === CONFIGURATION ===
DB_PATH = "users.db"
REMEDIES_DOCX = "Detailed Home Remedies for Common Diseases.docx"
EXERCISES_DOCX = "Physiotherapy Exercises.docx"  # Since they are in the same folder

# === CONNECT TO DB ===
def get_db_connection():
    conn = sqlite3.connect(DB_PATH)
    conn.row_factory = sqlite3.Row
    return conn

# === CREATE REMEDIES TABLE ===
def create_remedies_table():
    with get_db_connection() as conn:
        conn.execute('''CREATE TABLE IF NOT EXISTS remedies (
                            id INTEGER PRIMARY KEY AUTOINCREMENT,
                            symptom TEXT NOT NULL,
                            remedy TEXT NOT NULL
                        )''')
        conn.commit()

# === CREATE EXERCISES TABLE ===
def create_exercises_table():
    with get_db_connection() as conn:
        conn.execute('''CREATE TABLE IF NOT EXISTS exercises (
                            id INTEGER PRIMARY KEY AUTOINCREMENT,
                            condition TEXT NOT NULL,
                            exercise TEXT NOT NULL
                        )''')
        conn.commit()

# === GENERIC PARSER (Works for remedies or exercises) ===
def parse_docx(docx_path):
    doc = Document(docx_path)
    data = []

    current_title = None
    content_lines = []

    for para in doc.paragraphs:
        text = para.text.strip()
        if not text:
            continue

        # Match for symptom/condition titles (ex: "1. Back Pain")
        match = re.match(r'^\d+\.\s*(.+)', text)
        if match:
            if current_title and content_lines:
                full_text = ' '.join(content_lines).strip()
                data.append((current_title, full_text))  # Add the previous condition/remedy
                content_lines = []  # Reset for next item

            current_title = match.group(1).strip()  # Update the current symptom/condition
        elif current_title:
            content_lines.append(text)  # Collect content for current symptom/condition

    if current_title and content_lines:
        full_text = ' '.join(content_lines).strip()
        data.append((current_title, full_text))  # Add the last entry

    return data

# === INSERT INTO REMEDIES ===
def insert_remedies(remedies):
    with get_db_connection() as conn:
        conn.executemany(
            "INSERT INTO remedies (symptom, remedy) VALUES (?, ?)", remedies
        )
        conn.commit()
        print(f"✅ {len(remedies)} remedies inserted successfully.")

# === INSERT INTO EXERCISES ===
def insert_exercises(exercises):
    with get_db_connection() as conn:
        conn.executemany(
            "INSERT INTO exercises (condition, exercise) VALUES (?, ?)", exercises
        )
        conn.commit()
        print(f"✅ {len(exercises)} exercises inserted successfully.")

# === MAIN FUNCTION FOR EXECUTION ===
def process_remedies_and_exercises():
    # Process remedies
    create_remedies_table()
    remedies = parse_docx(REMEDIES_DOCX)
    insert_remedies(remedies)

    # Process exercises
    create_exercises_table()
    exercises = parse_docx(EXERCISES_DOCX)
    insert_exercises(exercises)

# === MAIN EXECUTION ===
if __name__ == "__main__":
    process_remedies_and_exercises()
