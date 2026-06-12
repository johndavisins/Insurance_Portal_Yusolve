import os, sqlite3
from datetime import datetime
from functools import wraps
from flask import flash
from flask_login import LoginManager, UserMixin, current_user
from werkzeug.security import generate_password_hash, check_password_hash

DB_PATH = os.path.join(os.path.dirname(os.path.abspath(__file__)), "yusolve.db")
login_manager = LoginManager()

def init_db():
    con = sqlite3.connect(DB_PATH)
    cur = con.cursor()
    cur.execute("""
        CREATE TABLE IF NOT EXISTS users (
            id            INTEGER PRIMARY KEY AUTOINCREMENT,
            first_name    TEXT NOT NULL DEFAULT '',
            last_name     TEXT NOT NULL DEFAULT '',
            email         TEXT UNIQUE NOT NULL,
            password_hash TEXT,
            role          TEXT NOT NULL DEFAULT 'user',
            auth_provider TEXT NOT NULL DEFAULT 'email',
            google_id     TEXT,
            created_at    TEXT NOT NULL
        )
    """)
    cur.execute("""
        CREATE TABLE IF NOT EXISTS download_history (
            id            INTEGER PRIMARY KEY AUTOINCREMENT,
            user_id       INTEGER NOT NULL,
            driver_name   TEXT NOT NULL,
            agency        TEXT DEFAULT '',
            filename      TEXT NOT NULL,
            downloaded_at TEXT NOT NULL,
            FOREIGN KEY (user_id) REFERENCES users(id) ON DELETE CASCADE
        )
    """)
    con.commit()
    con.close()

def _row(row):
    keys = ["id","first_name","last_name","email","password_hash","role","auth_provider","google_id","created_at"]
    return dict(zip(keys, row)) if row else None

def get_user_by_id(uid):
    con = sqlite3.connect(DB_PATH)
    row = con.execute("SELECT * FROM users WHERE id=?", (uid,)).fetchone()
    con.close(); return _row(row)

def get_user_by_email(email):
    con = sqlite3.connect(DB_PATH)
    row = con.execute("SELECT * FROM users WHERE email=?", (email,)).fetchone()
    con.close(); return _row(row)

def get_user_by_google_id(gid):
    con = sqlite3.connect(DB_PATH)
    row = con.execute("SELECT * FROM users WHERE google_id=?", (gid,)).fetchone()
    con.close(); return _row(row)

def get_all_users():
    con = sqlite3.connect(DB_PATH)
    rows = con.execute("SELECT * FROM users ORDER BY id").fetchall()
    con.close(); return [_row(r) for r in rows]

def create_user(first_name, last_name, email, password=None, role="user", auth_provider="email", google_id=None):
    pw_hash = generate_password_hash(password) if password else None
    now = datetime.utcnow().strftime("%Y-%m-%d %H:%M:%S")
    con = sqlite3.connect(DB_PATH)
    try:
        con.execute("INSERT INTO users (first_name,last_name,email,password_hash,role,auth_provider,google_id,created_at) VALUES (?,?,?,?,?,?,?,?)",
                    (first_name, last_name, email, pw_hash, role, auth_provider, google_id, now))
        con.commit()
        return get_user_by_email(email)
    except sqlite3.IntegrityError:
        return None
    finally:
        con.close()

def update_user_role(uid, role):
    con = sqlite3.connect(DB_PATH)
    con.execute("UPDATE users SET role=? WHERE id=?", (role, uid)); con.commit(); con.close()

def delete_user(uid):
    con = sqlite3.connect(DB_PATH)
    con.execute("DELETE FROM users WHERE id=?", (uid,)); con.commit(); con.close()

def verify_password(stored_hash, password):
    if not stored_hash: return False
    return check_password_hash(stored_hash, password)

def update_user_profile(uid, first_name, last_name, email):
    con = sqlite3.connect(DB_PATH)
    try:
        row = con.execute("SELECT id FROM users WHERE email=? AND id!=?", (email, uid)).fetchone()
        if row: return False, "Email already in use."
        con.execute("UPDATE users SET first_name=?, last_name=?, email=? WHERE id=?", (first_name, last_name, email, uid))
        con.commit(); return True, None
    except Exception as e:
        return False, str(e)
    finally:
        con.close()

def update_user_password(uid, new_password):
    pw_hash = generate_password_hash(new_password)
    con = sqlite3.connect(DB_PATH)
    con.execute("UPDATE users SET password_hash=? WHERE id=?", (pw_hash, uid)); con.commit(); con.close()

def log_download(user_id, driver_name, agency, filename):
    now = datetime.utcnow().strftime("%Y-%m-%d %H:%M:%S")
    con = sqlite3.connect(DB_PATH)
    con.execute("INSERT INTO download_history (user_id,driver_name,agency,filename,downloaded_at) VALUES (?,?,?,?,?)",
                (user_id, driver_name, agency, filename, now)); con.commit(); con.close()

def get_user_downloads(user_id):
    con = sqlite3.connect(DB_PATH)
    rows = con.execute("SELECT id,driver_name,agency,filename,downloaded_at FROM download_history WHERE user_id=? ORDER BY downloaded_at DESC", (user_id,)).fetchall()
    con.close()
    return [{"id":r[0],"driver_name":r[1],"agency":r[2],"filename":r[3],"downloaded_at":r[4]} for r in rows]

def delete_download_history(user_id):
    con = sqlite3.connect(DB_PATH)
    con.execute("DELETE FROM download_history WHERE user_id=?", (user_id,)); con.commit(); con.close()

class User(UserMixin):
    def __init__(self, data):
        self.id = data["id"]; self.first_name = data["first_name"]; self.last_name = data["last_name"]
        self.email = data["email"]; self.role = data["role"]; self.auth_provider = data["auth_provider"]
        self.google_id = data["google_id"]
        try: self.created_at = datetime.strptime(data["created_at"], "%Y-%m-%d %H:%M:%S")
        except: self.created_at = None

    @property
    def full_name(self): return f"{self.first_name} {self.last_name}".strip()
    @property
    def is_admin(self): return self.role == "admin"

@login_manager.user_loader
def load_user(uid):
    data = get_user_by_id(int(uid))
    return User(data) if data else None

# login_manager.login_view handles redirects for @login_required routes

def admin_required(f):
    @wraps(f)
    def decorated(*args, **kwargs):
        if not current_user.is_authenticated or not current_user.is_admin:
            flash("Admin access required.", "error")
            return redirect(url_for("index"))
        return f(*args, **kwargs)
    return decorated

def init_renewals_db():
    con = sqlite3.connect(DB_PATH)
    con.execute("""
        CREATE TABLE IF NOT EXISTS renewals (
            id            INTEGER PRIMARY KEY AUTOINCREMENT,
            company       TEXT NOT NULL,
            policy_type   TEXT NOT NULL,
            carrier       TEXT NOT NULL,
            renewal_date  TEXT NOT NULL,
            premium       TEXT NOT NULL DEFAULT '',
            policy_number TEXT NOT NULL DEFAULT '',
            agent_name    TEXT NOT NULL DEFAULT '',
            status        TEXT NOT NULL DEFAULT 'Active',
            auto_renew    INTEGER NOT NULL DEFAULT 1,
            created_by    INTEGER,
            created_at    TEXT NOT NULL,
            updated_at    TEXT NOT NULL
        )
    """)
    # Add new columns to existing DB if not present
    try:
        con.execute("ALTER TABLE renewals ADD COLUMN policy_number TEXT NOT NULL DEFAULT ''")
    except: pass
    try:
        con.execute("ALTER TABLE renewals ADD COLUMN agent_name TEXT NOT NULL DEFAULT ''")
    except: pass
    try:
        con.execute("ALTER TABLE renewals ADD COLUMN notes TEXT NOT NULL DEFAULT ''")
    except: pass
    # Renewal history table
    con.execute("""
        CREATE TABLE IF NOT EXISTS renewal_history (
            id           INTEGER PRIMARY KEY AUTOINCREMENT,
            renewal_id   INTEGER NOT NULL,
            company      TEXT NOT NULL,
            policy_type  TEXT NOT NULL,
            carrier      TEXT NOT NULL,
            renewal_date TEXT NOT NULL,
            premium      TEXT NOT NULL DEFAULT '',
            policy_number TEXT NOT NULL DEFAULT '',
            agent_name   TEXT NOT NULL DEFAULT '',
            notes        TEXT NOT NULL DEFAULT '',
            action       TEXT NOT NULL DEFAULT 'renewed',
            done_by      INTEGER,
            done_at      TEXT NOT NULL,
            FOREIGN KEY (renewal_id) REFERENCES renewals(id) ON DELETE CASCADE
        )
    """)
    con.commit(); con.close()

def get_all_renewals(user_id=None, is_admin=False):
    con = sqlite3.connect(DB_PATH)
    if is_admin or user_id is None:
        rows = con.execute("SELECT * FROM renewals ORDER BY renewal_date ASC").fetchall()
    else:
        rows = con.execute("SELECT * FROM renewals WHERE created_by=? ORDER BY renewal_date ASC", (user_id,)).fetchall()
    con.close()
    keys = ["id","company","policy_type","carrier","renewal_date","premium","policy_number","agent_name","notes","status","auto_renew","created_by","created_at","updated_at"]
    return [dict(zip(keys, r)) for r in rows]

def get_renewal_by_id(rid):
    con = sqlite3.connect(DB_PATH)
    row = con.execute("SELECT * FROM renewals WHERE id=?", (rid,)).fetchone()
    con.close()
    if not row: return None
    keys = ["id","company","policy_type","carrier","renewal_date","premium","policy_number","agent_name","notes","status","auto_renew","created_by","created_at","updated_at"]
    return dict(zip(keys, row))

def create_renewal(company, policy_type, carrier, renewal_date, premium, auto_renew, created_by, policy_number='', agent_name='', notes=''):
    now = datetime.utcnow().strftime("%Y-%m-%d %H:%M:%S")
    con = sqlite3.connect(DB_PATH)
    cur = con.execute(
        "INSERT INTO renewals (company,policy_type,carrier,renewal_date,premium,policy_number,agent_name,notes,status,auto_renew,created_by,created_at,updated_at) VALUES (?,?,?,?,?,?,?,?,?,?,?,?,?)",
        (company, policy_type, carrier, renewal_date, premium, policy_number, agent_name, notes, 'Active', 1 if auto_renew else 0, created_by, now, now)
    )
    rid = cur.lastrowid; con.commit(); con.close(); return rid

def update_renewal(rid, company, policy_type, carrier, renewal_date, premium, status, auto_renew, policy_number='', agent_name='', notes=''):
    now = datetime.utcnow().strftime("%Y-%m-%d %H:%M:%S")
    con = sqlite3.connect(DB_PATH)
    con.execute(
        "UPDATE renewals SET company=?,policy_type=?,carrier=?,renewal_date=?,premium=?,policy_number=?,agent_name=?,notes=?,status=?,auto_renew=?,updated_at=? WHERE id=?",
        (company, policy_type, carrier, renewal_date, premium, policy_number, agent_name, notes, status, 1 if auto_renew else 0, now, rid)
    )
    con.commit(); con.close()

def delete_renewal(rid):
    con = sqlite3.connect(DB_PATH)
    con.execute("DELETE FROM renewals WHERE id=?", (rid,)); con.commit(); con.close()

def renew_renewal(rid, done_by=None):
    """Push renewal_date forward by 1 year and save history"""
    from dateutil.relativedelta import relativedelta
    r = get_renewal_by_id(rid)
    if not r: return
    try:
        old_date = datetime.strptime(r["renewal_date"], "%Y-%m-%d")
        new_date = (old_date + relativedelta(years=1)).strftime("%Y-%m-%d")
    except:
        return
    now = datetime.utcnow().strftime("%Y-%m-%d %H:%M:%S")
    con = sqlite3.connect(DB_PATH)
    # Save to history before updating
    con.execute(
        "INSERT INTO renewal_history (renewal_id,company,policy_type,carrier,renewal_date,premium,policy_number,agent_name,notes,action,done_by,done_at) VALUES (?,?,?,?,?,?,?,?,?,?,?,?)",
        (rid, r["company"], r["policy_type"], r["carrier"], r["renewal_date"],
         r.get("premium",""), r.get("policy_number",""), r.get("agent_name",""),
         r.get("notes",""), "renewed", done_by, now)
    )
    con.execute("UPDATE renewals SET renewal_date=?,status='Active',updated_at=? WHERE id=?", (new_date, now, rid))
    con.commit(); con.close()

def get_renewal_history(renewal_id):
    con = sqlite3.connect(DB_PATH)
    rows = con.execute(
        "SELECT * FROM renewal_history WHERE renewal_id=? ORDER BY done_at DESC", (renewal_id,)
    ).fetchall()
    con.close()
    keys = ["id","renewal_id","company","policy_type","carrier","renewal_date","premium","policy_number","agent_name","notes","action","done_by","done_at"]
    return [dict(zip(keys, r)) for r in rows]

def get_all_renewal_history():
    con = sqlite3.connect(DB_PATH)
    rows = con.execute(
        "SELECT * FROM renewal_history ORDER BY done_at DESC LIMIT 100"
    ).fetchall()
    con.close()
    keys = ["id","renewal_id","company","policy_type","carrier","renewal_date","premium","policy_number","agent_name","notes","action","done_by","done_at"]
    return [dict(zip(keys, r)) for r in rows]


def _pay_keys(): return ["id","company","policy_number","carrier","amount","due_date","paid_date","status","payment_method","bank_name","reference_num","note","created_by","created_at"]

def get_all_payments(user_id=None, is_admin=False):
    import sqlite3 as _sq
    from auth import DB_PATH as _DB
    con = _sq.connect(_DB)
    if is_admin or user_id is None:
        rows = con.execute("SELECT * FROM payments ORDER BY due_date ASC").fetchall()
    else:
        rows = con.execute("SELECT * FROM payments WHERE created_by=? ORDER BY due_date ASC", (user_id,)).fetchall()
    con.close()
    return [dict(zip(_pay_keys(), r)) for r in rows]

def get_payment_by_id(pid):
    import sqlite3 as _sq
    from auth import DB_PATH as _DB
    con = _sq.connect(_DB)
    row = con.execute("SELECT * FROM payments WHERE id=?", (pid,)).fetchone()
    con.close()
    return dict(zip(_pay_keys(), row)) if row else None

def create_payment(company, policy_number, carrier, amount, due_date, note, created_by, payment_method='', bank_name='', reference_num=''):
    import sqlite3 as _sq
    from auth import DB_PATH as _DB
    from datetime import datetime as _dt
    now = _dt.utcnow().strftime("%Y-%m-%d %H:%M:%S")
    con = _sq.connect(_DB)
    con.execute(
        "INSERT INTO payments (company,policy_number,carrier,amount,due_date,status,payment_method,bank_name,reference_num,note,created_by,created_at) VALUES (?,?,?,?,?,?,?,?,?,?,?,?)",
        (company, policy_number, carrier, float(amount or 0), due_date, "Pending", payment_method, bank_name, reference_num, note, created_by, now)
    )
    con.commit(); con.close()

def mark_payment_paid(pid, paid_date, done_by=None, done_by_name=''):
    import sqlite3 as _sq
    from auth import DB_PATH as _DB
    from datetime import datetime as _dt
    now = _dt.utcnow().strftime("%Y-%m-%d %H:%M:%S")
    con = _sq.connect(_DB)
    row = con.execute("SELECT status FROM payments WHERE id=?", (pid,)).fetchone()
    old_status = row[0] if row else ''
    con.execute("UPDATE payments SET status='Paid',paid_date=? WHERE id=?", (paid_date, pid))
    con.execute(
        "INSERT INTO payment_history (payment_id,action,old_status,new_status,done_by,done_by_name,done_at) VALUES (?,?,?,?,?,?,?)",
        (pid, 'marked_paid', old_status, 'Paid', done_by, done_by_name, now)
    )
    con.commit(); con.close()

def get_payment_history(pid):
    import sqlite3 as _sq
    from auth import DB_PATH as _DB
    con = _sq.connect(_DB)
    rows = con.execute(
        "SELECT * FROM payment_history WHERE payment_id=? ORDER BY done_at DESC", (pid,)
    ).fetchall()
    con.close()
    keys = ["id","payment_id","action","old_status","new_status","note","done_by","done_by_name","done_at"]
    return [dict(zip(keys, r)) for r in rows]

def update_payment(pid, company, policy_number, carrier, amount, due_date, status, note, payment_method='', bank_name='', reference_num='', done_by=None, done_by_name=''):
    import sqlite3 as _sq
    from auth import DB_PATH as _DB
    from datetime import datetime as _dt
    now = _dt.utcnow().strftime("%Y-%m-%d %H:%M:%S")
    con = _sq.connect(_DB)
    row = con.execute("SELECT status FROM payments WHERE id=?", (pid,)).fetchone()
    old_status = row[0] if row else ''
    con.execute(
        "UPDATE payments SET company=?,policy_number=?,carrier=?,amount=?,due_date=?,status=?,payment_method=?,bank_name=?,reference_num=?,note=? WHERE id=?",
        (company, policy_number, carrier, float(amount or 0), due_date, status, payment_method, bank_name, reference_num, note, pid)
    )
    if old_status != status:
        con.execute(
            "INSERT INTO payment_history (payment_id,action,old_status,new_status,note,done_by,done_by_name,done_at) VALUES (?,?,?,?,?,?,?,?)",
            (pid, 'status_changed', old_status, status, f'Updated by {done_by_name}', done_by, done_by_name, now)
        )
    con.commit(); con.close()

def delete_payment(pid):
    import sqlite3 as _sq
    from auth import DB_PATH as _DB
    con = _sq.connect(_DB)
    con.execute("DELETE FROM payments WHERE id=?", (pid,)); con.commit(); con.close()
