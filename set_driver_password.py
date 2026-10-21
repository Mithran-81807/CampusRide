
import getpass
import mysql.connector
from werkzeug.security import generate_password_hash
from dotenv import load_dotenv
import os

load_dotenv()

conn = mysql.connector.connect(
    host=os.getenv("DB_HOST", "127.0.0.1"),
    port=int(os.getenv("DB_PORT", "3306")),
    user=os.getenv("DB_USER", "root"),
    password=os.getenv("DB_PASSWORD", ""),
    database=os.getenv("DB_NAME", "campusride_db"),
)

try:
    cursor = conn.cursor(dictionary=True)

    cursor.execute(
        "SELECT driver_id, name, phone FROM DRIVER ORDER BY driver_id"
    )
    drivers = cursor.fetchall()

    for driver in drivers:
        print(
            f"\nDriver ID: {driver['driver_id']} | "
            f"{driver['name']} | {driver['phone']}"
        )
        password = getpass.getpass("Set password (min 8 characters): ")

        if len(password) < 8:
            print("Password too short. Skipping this driver.")
            continue

        password_hash = generate_password_hash(password)

        cursor.execute(
            "UPDATE DRIVER SET password_hash = %s WHERE driver_id = %s",
            (password_hash, driver["driver_id"]),
        )
        conn.commit()
        print("Password saved securely.")

    cursor.close()
finally:
    conn.close()

print("\nDriver password setup finished.")
