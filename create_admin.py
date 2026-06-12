from auth import init_db, create_user, get_user_by_email
import sqlite3, os
from auth import DB_PATH

init_db()

email = input("Admin email: ").strip().lower()
password = input("Admin password: ").strip()
first = input("First name: ").strip()
last  = input("Last name: ").strip()

existing = get_user_by_email(email)
if existing:
    con = sqlite3.connect(DB_PATH)
    con.execute("UPDATE users SET role='admin' WHERE email=?", (email,))
    con.commit(); con.close()
    print(f"User {email} promoted to admin.")
else:
    data = create_user(first, last, email, password=password, role="admin")
    if data:
        print(f"Admin created: {email}")
    else:
        print("Failed to create admin.")
