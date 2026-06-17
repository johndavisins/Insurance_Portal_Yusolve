import os, random
BASE_DIR = os.path.dirname(os.path.abspath(__file__))
from datetime import date, timedelta, datetime
from io import BytesIO
from dateutil.relativedelta import relativedelta
from flask import Flask, render_template, request, send_file, jsonify, redirect, url_for, flash, session
from flask_login import login_user, logout_user, login_required, current_user
import pypdf
from reportlab.pdfgen import canvas as rl_canvas
from reportlab.lib.pagesizes import LETTER
from auth import (init_db, login_manager, admin_required, get_user_by_email,
                  get_user_by_google_id, get_all_users, create_user, update_user_role,
                  delete_user, verify_password, User, get_user_by_id,
                  update_user_profile, update_user_password, log_download,
                  get_user_downloads, delete_download_history,
                  init_renewals_db, get_all_renewals, get_renewal_by_id,
                  create_renewal, update_renewal, delete_renewal, renew_renewal,
                  get_renewal_history, get_all_renewal_history,
                  get_all_payments, get_payment_by_id, create_payment,
                  mark_payment_paid, get_payment_history, update_payment, delete_payment,
                  get_all_agents, create_agent, delete_agent,
                  get_quotes_for_renewal, add_quote, delete_quote)

app = Flask(__name__)

# Secret key: persisted to disk so sessions survive restarts, never hardcoded
_SECRET_KEY_FILE = os.path.join(BASE_DIR, ".secret_key")
def _get_or_create_secret_key():
    env_key = os.environ.get("SECRET_KEY")
    if env_key:
        return env_key
    if os.path.exists(_SECRET_KEY_FILE):
        with open(_SECRET_KEY_FILE, "r") as f:
            key = f.read().strip()
            if key:
                return key
    import secrets as _secrets
    key = _secrets.token_hex(32)
    try:
        with open(_SECRET_KEY_FILE, "w") as f:
            f.write(key)
    except Exception:
        pass
    return key

app.secret_key = _get_or_create_secret_key()

# Session / cookie security
app.config["SESSION_COOKIE_HTTPONLY"] = True
app.config["SESSION_COOKIE_SAMESITE"] = "Lax"
app.config["SESSION_COOKIE_SECURE"] = os.environ.get("FLASK_ENV") == "production"
app.config["PERMANENT_SESSION_LIFETIME"] = timedelta(days=14)
app.config["REMEMBER_COOKIE_DURATION"] = timedelta(days=14)
app.config["REMEMBER_COOKIE_HTTPONLY"] = True
app.config["REMEMBER_COOKIE_SAMESITE"] = "Lax"
login_manager.init_app(app)
login_manager.login_view = "login"



BLANK_PDF = os.path.join(os.path.dirname(os.path.abspath(__file__)), "Exp_form_sample.pdf")
init_db()
init_renewals_db()

# ── Auth Routes ───────────────────────────────────────────────────────────────

# In-memory brute-force protection: tracks failed attempts per email+IP.
# Resets on successful login or after LOCKOUT_WINDOW expires.
_login_attempts = {}  # key -> {"count": int, "first_attempt": datetime}
LOCKOUT_THRESHOLD = 5
LOCKOUT_WINDOW = timedelta(minutes=15)

def _login_key(email, ip):
    return f"{email}|{ip}"

def _is_locked_out(email, ip):
    key = _login_key(email, ip)
    entry = _login_attempts.get(key)
    if not entry:
        return False, 0
    if datetime.utcnow() - entry["first_attempt"] > LOCKOUT_WINDOW:
        del _login_attempts[key]
        return False, 0
    if entry["count"] >= LOCKOUT_THRESHOLD:
        remaining = LOCKOUT_WINDOW - (datetime.utcnow() - entry["first_attempt"])
        return True, max(1, int(remaining.total_seconds() // 60) + 1)
    return False, 0

def _record_failed_attempt(email, ip):
    key = _login_key(email, ip)
    entry = _login_attempts.get(key)
    if not entry or datetime.utcnow() - entry["first_attempt"] > LOCKOUT_WINDOW:
        _login_attempts[key] = {"count": 1, "first_attempt": datetime.utcnow()}
    else:
        entry["count"] += 1

def _clear_attempts(email, ip):
    _login_attempts.pop(_login_key(email, ip), None)

@app.route("/login", methods=["GET","POST"])
def login():
    if current_user.is_authenticated:
        return redirect(url_for("index"))
    if request.method == "POST":
        email    = request.form.get("email","").strip().lower()
        password = request.form.get("password","")
        ip       = request.remote_addr or "unknown"

        locked, minutes_left = _is_locked_out(email, ip)
        if locked:
            flash(f"Too many failed attempts. Please try again in {minutes_left} minute(s).", "error")
            return render_template("login.html")

        data = get_user_by_email(email)
        if not data or data["auth_provider"] != "email" or not verify_password(data["password_hash"], password):
            _record_failed_attempt(email, ip)
            flash("Invalid email or password.", "error")
            return render_template("login.html")

        _clear_attempts(email, ip)
        login_user(User(data), remember=True)
        session.permanent = True
        return redirect(url_for("index"))
    return render_template("login.html")

@app.route("/register", methods=["GET","POST"])
def register():
    if current_user.is_authenticated:
        return redirect(url_for("index"))
    if request.method == "POST":
        first_name = request.form.get("first_name","").strip()
        last_name  = request.form.get("last_name","").strip()
        email      = request.form.get("email","").strip().lower()
        password   = request.form.get("password","")
        confirm    = request.form.get("confirm_password","")
        if not all([first_name, last_name, email, password]):
            flash("All fields are required.", "error"); return render_template("register.html")
        if len(password) < 8:
            flash("Password must be at least 8 characters.", "error"); return render_template("register.html")
        if password != confirm:
            flash("Passwords do not match.", "error"); return render_template("register.html")
        if get_user_by_email(email):
            flash("Account with this email already exists.", "error"); return render_template("register.html")
        data = create_user(first_name, last_name, email, password=password)
        if not data:
            flash("Registration failed.", "error"); return render_template("register.html")
        login_user(User(data), remember=True)
        flash(f"Welcome, {first_name}!", "success")
        return redirect(url_for("index"))
    return render_template("register.html")

@app.route("/logout")
@login_required
def logout():
    logout_user()
    flash("You have been signed out.", "success")
    return redirect(url_for("login"))



# ── Profile ───────────────────────────────────────────────────────────────────

@app.route("/profile")
@login_required
def profile():
    downloads = get_user_downloads(current_user.id)
    return render_template("profile.html", downloads=downloads)

@app.route("/profile/update", methods=["POST"])
@login_required
def profile_update():
    first_name = request.form.get("first_name","").strip()
    last_name  = request.form.get("last_name","").strip()
    email      = request.form.get("email","").strip().lower()
    if not all([first_name, last_name, email]):
        flash("All fields required.", "error"); return redirect(url_for("profile"))
    ok, err = update_user_profile(current_user.id, first_name, last_name, email)
    if ok:
        data = get_user_by_id(current_user.id)
        login_user(User(data), remember=True)
        flash("Profile updated.", "success")
    else:
        flash(err or "Update failed.", "error")
    return redirect(url_for("profile"))

@app.route("/profile/change-password", methods=["POST"])
@login_required
def profile_change_password():
    if current_user.auth_provider == "google":
        flash("Password change not available for Google accounts.", "error"); return redirect(url_for("profile"))
    current_pw = request.form.get("current_password","")
    new_pw     = request.form.get("new_password","")
    confirm_pw = request.form.get("confirm_password","")
    data = get_user_by_id(current_user.id)
    if not verify_password(data["password_hash"], current_pw):
        flash("Current password is incorrect.", "error"); return redirect(url_for("profile"))
    if len(new_pw) < 8:
        flash("Password must be at least 8 characters.", "error"); return redirect(url_for("profile"))
    if new_pw != confirm_pw:
        flash("Passwords do not match.", "error"); return redirect(url_for("profile"))
    update_user_password(current_user.id, new_pw)
    flash("Password changed.", "success"); return redirect(url_for("profile"))

@app.route("/profile/clear-history", methods=["POST"])
@login_required
def profile_clear_history():
    delete_download_history(current_user.id)
    flash("Download history cleared.", "success"); return redirect(url_for("profile"))

# ── Admin ─────────────────────────────────────────────────────────────────────

@app.route("/admin")
@login_required
@admin_required
def admin_panel():
    from datetime import datetime as dt
    users_raw = get_all_users()
    today = date.today()

    users = []
    for u in users_raw:
        user_obj = User(u)
        uid = u["id"]

        # Get renewals for this user
        user_renewals = get_all_renewals(user_id=uid, is_admin=False)
        urgent = sum(1 for r in user_renewals if (lambda d: (dt.strptime(d, "%Y-%m-%d").date() - today).days <= 30 if d else False)(r.get("renewal_date","")))

        # Get payments for this user
        user_payments = get_all_payments(user_id=uid, is_admin=False)
        overdue = 0
        outstanding = 0
        for p in user_payments:
            if p["status"] != "Paid":
                outstanding += p["amount"]
                try:
                    dd = dt.strptime(p["due_date"], "%Y-%m-%d").date()
                    if (dd - today).days < 0:
                        overdue += 1
                except: pass

        users.append({
            "user": user_obj,
            "id": uid,
            "renewals_count": len(user_renewals),
            "renewals_urgent": urgent,
            "payments_count": len(user_payments),
            "payments_overdue": overdue,
            "outstanding": outstanding,
        })

    # Global stats
    all_renewals = get_all_renewals(is_admin=True)
    all_payments = get_all_payments(is_admin=True)
    global_stats = {
        "total_renewals": len(all_renewals),
        "total_payments": len(all_payments),
        "total_outstanding": sum(p["amount"] for p in all_payments if p["status"] != "Paid"),
        "total_overdue": sum(1 for p in all_payments if p["status"] == "Overdue"),
    }

    return render_template("admin.html", users=[User(u) for u in users_raw],
                            user_stats=users, global_stats=global_stats)

@app.route("/admin/make-admin/<int:uid>", methods=["POST"])
@login_required
@admin_required
def make_admin(uid):
    if uid == current_user.id:
        flash("Cannot change your own role.", "error"); return redirect(url_for("admin_panel"))
    update_user_role(uid, "admin"); flash("User promoted to admin.", "success"); return redirect(url_for("admin_panel"))

@app.route("/admin/remove-admin/<int:uid>", methods=["POST"])
@login_required
@admin_required
def remove_admin(uid):
    if uid == current_user.id:
        flash("Cannot change your own role.", "error"); return redirect(url_for("admin_panel"))
    update_user_role(uid, "user"); flash("Admin role removed.", "success"); return redirect(url_for("admin_panel"))

@app.route("/admin/delete-user/<int:uid>", methods=["POST"])
@login_required
@admin_required
def delete_user_route(uid):
    if uid == current_user.id:
        flash("Cannot delete your own account.", "error"); return redirect(url_for("admin_panel"))
    delete_user(uid); flash("User deleted.", "success"); return redirect(url_for("admin_panel"))

# ── Tools ─────────────────────────────────────────────────────────────────────

@app.route("/")
@login_required
def index():
    from datetime import datetime as dt
    today = date.today()

    # Renewals
    all_r = get_all_renewals(user_id=current_user.id, is_admin=current_user.is_admin)
    for r in all_r:
        try:
            rd = dt.strptime(r["renewal_date"], "%Y-%m-%d").date()
            r["days"] = (rd - today).days
            r["date_fmt"] = rd.strftime("%m/%d/%Y")
        except:
            r["days"] = 999
            r["date_fmt"] = r["renewal_date"]
        if r["days"] <= 30:   r["color"] = "red"
        elif r["days"] <= 60: r["color"] = "yellow"
        else:                  r["color"] = "green"
        r["carrier"] = r.get("carrier", "")
        r["policy_type"] = r.get("policy_type", "")
    all_r_sorted = sorted(all_r, key=lambda x: x["days"])

    # Payments
    all_p = get_all_payments(user_id=current_user.id, is_admin=current_user.is_admin)
    for p in all_p:
        try:
            dd = dt.strptime(p["due_date"], "%Y-%m-%d").date()
            p["days_left"] = (dd - today).days
            p["due_fmt"] = dd.strftime("%m/%d/%Y")
        except:
            p["days_left"] = 0
            p["due_fmt"] = p["due_date"]
        if p["status"] == "Paid":
            p["color"] = "green"
        elif p["days_left"] < 0:
            p["color"] = "red"
            p["status"] = "Overdue"
        elif p["days_left"] <= 7:
            p["color"] = "yellow"
        else:
            p["color"] = "blue"

    overdue_p = [p for p in all_p if p["color"] == "red"]
    due_soon_p = [p for p in all_p if p["color"] == "yellow"]
    recent_p = sorted([p for p in all_p if p["status"] != "Paid"],
                      key=lambda x: x["days_left"])[:4]

    stats = {
        "renewals_urgent":    sum(1 for x in all_r if x["days"] <= 30),
        "renewals_upcoming":  sum(1 for x in all_r if 30 < x["days"] <= 60),
        "renewals_total":     len(all_r),
        "payments_overdue":   len(overdue_p),
        "payments_due_soon":  len(due_soon_p),
        "payments_outstanding": sum(p["amount"] for p in all_p if p["status"] != "Paid"),
    }
    return render_template("dashboard.html",
        renewals=all_r_sorted[:6],
        recent_payments=recent_p,
        stats=stats,
        no_renewals=len(all_r)==0,
        no_payments=len(all_p)==0
    )

@app.route("/exp-form")
@login_required
def exp_form():
    return render_template("exp_form.html")

@app.route("/certificate")
@login_required
def certificate():
    return render_template("certificate.html")

# ── PDF Generation ────────────────────────────────────────────────────────────

COMPANIES = [
    {"name":"UNITED PATRIOT EXPRESS LP","addr":"3269 Broad St, OMAHA, NE 96328","dot":"1424652","ph":"(873) 834-9216","sups":['JOSEPH LOPEZ', 'JOHN ANDERSON', 'JAMES BROWN']},
    {"name":"SWIFT FREIGHT SYSTEMS INC","addr":"8351 Highway Dr, AUSTIN, TX 92121","dot":"2706142","ph":"(545) 725-8844","sups":['ELIZABETH TAYLOR', 'ROBERT THOMAS', 'MARIA WILSON']},
    {"name":"HEARTLAND CARRIERS LP","addr":"2564 Trucking Ln, LAREDO, TX 61752","dot":"2423367","ph":"(661) 966-7399","sups":['MIGUEL BROWN', 'MIGUEL SMITH', 'SOFIA HERNANDEZ']},
    {"name":"GREEN VALLEY EXPRESS INC","addr":"1968 Eastgate Dr, SHREVEPORT, LA 91063","dot":"3903315","ph":"(211) 947-1975","sups":['WILLIAM THOMPSON', 'ANA LEWIS', 'ELIZABETH CLARK']},
    {"name":"CROWN TRUCKING CO HOLDINGS INC","addr":"3461 Highway Dr, SALT LAKE CITY, UT 97446","dot":"994766","ph":"(642) 346-1164","sups":['MIGUEL WILLIAMS', 'LINDA BROWN', 'JOHN THOMPSON']},
    {"name":"COVENANT ROEHL TRANSPORT GROUP LLC","addr":"3957 Distribution Center Rd, OKLAHOMA CITY, OK 57710","dot":"2045450","ph":"(942) 262-1187","sups":['SUSAN GONZALEZ', 'JOSE HERNANDEZ', 'ANTONIO JOHNSON']},
    {"name":"ROAD KING OLD DOMINION SHIPPING HOLDINGS INC","addr":"2760 Depot St, NASHVILLE, TN 16736","dot":"2570862","ph":"(649) 607-7160","sups":['SUSAN JOHNSON', 'PATRICIA ANDERSON', 'MARY THOMAS']},
    {"name":"ESTES CARRIERS CORP","addr":"4025 Freight Way, WICHITA, KS 79874","dot":"1168248","ph":"(828) 434-8222","sups":['JESSICA WHITE', 'MIGUEL SMITH', 'PATRICIA MARTIN']},
    {"name":"PLAINS HERITAGE HAULING CORP","addr":"7643 Main St, LUBBOCK, TX 61488","dot":"2934718","ph":"(479) 923-8410","sups":['JOSE WILSON', 'LAURA PEREZ', 'CHARLES SANCHEZ']},
    {"name":"WERNER HERITAGE LOGISTICS LLC GROUP LLC","addr":"1710 Fleet St, TOLEDO, OH 39624","dot":"1995327","ph":"(807) 878-7087","sups":['JOSEPH MARTINEZ', 'RICHARD MOORE', 'JENNIFER THOMPSON']},
    {"name":"APEX FREIGHTWAYS ENTERPRISES LLC","addr":"930 Freight Way, LAS VEGAS, NV 14284","dot":"3244220","ph":"(266) 562-2213","sups":['SUSAN RAMIREZ', 'SOFIA THOMAS', 'ELIZABETH SANCHEZ']},
    {"name":"CROSS COUNTRY TRANSPORTATION ENTERPRISES LLC","addr":"2264 Trucking Ln, FORT WAYNE, IN 18762","dot":"3320114","ph":"(280) 428-9574","sups":['JESSICA LEE', 'MICHAEL LEWIS', 'ANTONIO BROWN']},
    {"name":"MOMENTUM HAULING ENTERPRISES LLC","addr":"2403 Terminal Rd, AKRON, OH 32041","dot":"3168037","ph":"(630) 662-1857","sups":['SARAH RAMIREZ', 'MIGUEL BROWN', 'ANA SANCHEZ']},
    {"name":"LIBERTY PRIME CARRIERS LLC","addr":"7375 Industrial Pkwy, JOPLIN, MO 94838","dot":"1594115","ph":"(984) 566-1716","sups":['WILLIAM JOHNSON', 'JOSEPH HERNANDEZ', 'LAURA SANCHEZ']},
    {"name":"VANGUARD VANGUARD CARRIERS INC INC","addr":"9131 Commerce Dr, MILWAUKEE, WI 77608","dot":"1738088","ph":"(966) 773-4635","sups":['SOFIA HARRIS', 'LINDA GONZALEZ', 'LINDA JOHNSON']},
    {"name":"ZENITH TRUCKING CO HOLDINGS INC","addr":"7294 Westside Dr, KANSAS CITY, MO 17832","dot":"1756807","ph":"(351) 882-2569","sups":['JENNIFER SANCHEZ', 'DAVID CLARK', 'JESSICA GONZALEZ']},
    {"name":"FOUNDERS ROAD KING TRANSPORTATION LP","addr":"9585 Commerce Dr, COLUMBIA, SC 66771","dot":"580332","ph":"(653) 549-4499","sups":['PATRICIA WILLIAMS', 'THOMAS CLARK', 'ANTONIO MILLER']},
    {"name":"LAKESIDE LOGISTICS HOLDINGS INC","addr":"5078 Main St, COLUMBUS, OH 35672","dot":"2998317","ph":"(759) 680-4591","sups":['SOFIA BROWN', 'SOFIA GONZALEZ', 'JESSICA PEREZ']},
    {"name":"NATIONAL CARRIERS INC CORP","addr":"4482 Fleet St, PHOENIX, AZ 45024","dot":"472382","ph":"(369) 738-8228","sups":['SARAH RODRIGUEZ', 'DAVID BROWN', 'ANTONIO RODRIGUEZ']},
    {"name":"NEXUS SUMMIT TRANSPORT LLC GROUP LLC","addr":"8060 Highway Dr, SALT LAKE CITY, UT 80811","dot":"2589020","ph":"(412) 698-7934","sups":['MARIA CLARK', 'JESSICA SANCHEZ', 'SOFIA MARTIN']},
    {"name":"LIBERTY EASTERN TRANSPORT SERVICES LP","addr":"9872 Broad St, SHREVEPORT, LA 81904","dot":"2399064","ph":"(283) 728-5655","sups":['ANTONIO GARCIA', 'ELIZABETH GONZALEZ', 'JOSE HARRIS']},
    {"name":"CARGO MASTER EXPRESS INC","addr":"2585 Industrial Pkwy, LITTLE ROCK, AR 10031","dot":"3161239","ph":"(353) 695-6820","sups":['DIANA ANDERSON', 'SOFIA HERNANDEZ', 'RICHARD JOHNSON']},
    {"name":"GOLD KNIGHT LOGISTICS LLC GROUP LLC","addr":"9761 Depot St, DENVER, CO 21368","dot":"480987","ph":"(289) 855-4816","sups":['LINDA HARRIS', 'MARY MOORE', 'JENNIFER WILSON']},
    {"name":"EXPRESS STAR TRANSPORT LLC ENTERPRISES LLC","addr":"9701 Distribution Center Rd, ALBUQUERQUE, NM 22125","dot":"560069","ph":"(202) 630-5636","sups":['MIGUEL MOORE', 'ANTONIO BROWN', 'DAVID GARCIA']},
    {"name":"INTERSTATE EXPRESS CORP","addr":"1118 Industrial Pkwy, JACKSON, MS 24264","dot":"3430928","ph":"(216) 579-5134","sups":['SUSAN JOHNSON', 'KAREN BROWN', 'CHARLES LOPEZ']},
    {"name":"FREIGHT LOGISTICS GROUP LLC","addr":"8558 Corporate Dr, COLUMBIA, SC 13035","dot":"213814","ph":"(346) 770-1205","sups":['JOSE SMITH', 'JOHN GONZALEZ', 'MICHAEL WILLIAMS']},
    {"name":"MOMENTUM TURNPIKE LOGISTICS LLC LLC","addr":"3247 Park Ave, BATON ROUGE, LA 44248","dot":"801609","ph":"(550) 551-5999","sups":['JESSICA MARTIN', 'JOSE RODRIGUEZ', 'LUIS HARRIS']},
    {"name":"THOMAS SHIPPING GROUP LLC","addr":"2937 Logistics Blvd, SHREVEPORT, LA 68919","dot":"3102209","ph":"(710) 203-3001","sups":['LUIS LEWIS', 'MIGUEL MOORE', 'MIGUEL DAVIS']},
    {"name":"JONES CARRIERS INC","addr":"4608 Park Ave, SPRINGFIELD, MO 41524","dot":"2128869","ph":"(753) 771-2138","sups":['ROBERT JONES', 'PATRICIA SMITH', 'KAREN ANDERSON']},
    {"name":"ZENITH TRANSPORT LLC","addr":"1129 Highway Dr, JACKSON, MS 44725","dot":"462786","ph":"(594) 436-6310","sups":['MIGUEL MARTINEZ', 'SOFIA JACKSON', 'WILLIAM WHITE']},
    {"name":"HORIZON CROSS COUNTRY LINES GROUP LLC","addr":"4966 Southpoint Dr, LUBBOCK, TX 57784","dot":"1557201","ph":"(513) 879-8384","sups":['KAREN SANCHEZ', 'MARIA THOMAS', 'LINDA CLARK']},
    {"name":"PATRIOT TRANSPORT SERVICES CORP","addr":"7579 Distribution Center Rd, BATON ROUGE, LA 57017","dot":"2341299","ph":"(323) 390-7347","sups":['ROBERT DAVIS', 'JOHN HARRIS', 'SUSAN GARCIA']},
    {"name":"HARRIS HAULING ENTERPRISES LLC","addr":"8942 Freight Way, OKLAHOMA CITY, OK 49187","dot":"2270160","ph":"(207) 537-6770","sups":['JAMES LEWIS', 'WILLIAM WILSON', 'KAREN RAMIREZ']},
    {"name":"EASTERN EAGLE FREIGHT LLC","addr":"3329 Industrial Pkwy, DES MOINES, IA 17832","dot":"791425","ph":"(213) 238-4663","sups":['SARAH RAMIREZ', 'DIANA MOORE', 'THOMAS WILLIAMS']},
    {"name":"DESERT LOGISTICS LLC HOLDINGS INC","addr":"1102 Terminal Rd, BATON ROUGE, LA 91783","dot":"2550827","ph":"(506) 723-2804","sups":['CHARLES GARCIA', 'MICHAEL RAMIREZ', 'LAURA THOMPSON']},
    {"name":"GONZALEZ TRUCKING CO INC","addr":"9561 Cargo Way, GREENSBORO, NC 88702","dot":"2041257","ph":"(941) 565-2117","sups":['DAVID ANDERSON', 'MARIA WILSON', 'DAVID LOPEZ']},
    {"name":"ANDERSON HAULING CORP","addr":"1520 Broad St, ALBUQUERQUE, NM 72386","dot":"3711533","ph":"(708) 798-8163","sups":['SOFIA MOORE', 'SOFIA ANDERSON', 'JOSEPH HERNANDEZ']},
    {"name":"SYNERGY LIBERTY BELL FREIGHTWAYS LP","addr":"3024 Westside Dr, KANSAS CITY, MO 86989","dot":"1323414","ph":"(371) 654-5279","sups":['JESSICA ANDERSON', 'CHARLES GARCIA', 'ANTONIO GONZALEZ']},
    {"name":"FOUNDERS PLAINS FREIGHT LLC","addr":"363 Westside Dr, DAYTON, OH 99596","dot":"320829","ph":"(802) 731-2280","sups":['DAVID MARTINEZ', 'KAREN PEREZ', 'JOHN GONZALEZ']},
    {"name":"ALL AMERICAN DIAMOND FREIGHTWAYS LP","addr":"4233 Eastgate Dr, KNOXVILLE, TN 98140","dot":"1796882","ph":"(706) 409-4379","sups":['DAVID ROBINSON', 'JOHN LEE', 'JESSICA LEE']},
    {"name":"HAWK SOUTHERN TRANSPORT LLC GROUP LLC","addr":"9219 Fleet St, MILWAUKEE, WI 37215","dot":"3412393","ph":"(851) 399-1357","sups":['THOMAS ANDERSON', 'DAVID TAYLOR', 'LAURA HERNANDEZ']},
    {"name":"MARTIN LOGISTICS HOLDINGS INC","addr":"8085 Broad St, AMARILLO, TX 68748","dot":"738888","ph":"(261) 746-6479","sups":['CHARLES JOHNSON', 'JOSEPH BROWN', 'WILLIAM LEE']},
    {"name":"LEGACY SHIPPING LP","addr":"4091 Freight Way, OKLAHOMA CITY, OK 65565","dot":"2665324","ph":"(806) 791-9344","sups":['DAVID PEREZ', 'JAMES JONES', 'MICHAEL MOORE']},
    {"name":"APEX LOGISTICS GROUP INC","addr":"3284 Westside Dr, DALLAS, TX 11744","dot":"2983739","ph":"(385) 731-2220","sups":['JESSICA MILLER', 'JOHN HERNANDEZ', 'MARIA MARTIN']},
    {"name":"PACIFIC PIONEER CARRIERS CO","addr":"6106 Distribution Center Rd, KANSAS CITY, MO 21470","dot":"2784568","ph":"(515) 456-8556","sups":['JOSEPH ROBINSON', 'CARLOS HERNANDEZ', 'DIANA TAYLOR']},
    {"name":"HAWK LINES LLC","addr":"3519 Eastgate Dr, CHICAGO, IL 42433","dot":"1897793","ph":"(402) 284-6787","sups":['SARAH SANCHEZ', 'LAURA ROBINSON', 'KAREN ANDERSON']},
    {"name":"NEXUS LIBERTY BELL CARRIERS INC","addr":"2406 Business Center Dr, KNOXVILLE, TN 89197","dot":"1680325","ph":"(347) 710-8662","sups":['ANA HERNANDEZ', 'SOFIA HERNANDEZ', 'SARAH HARRIS']},
    {"name":"USA TITAN SHIPPING GROUP LLC","addr":"5838 Main St, BATON ROUGE, LA 18276","dot":"3541700","ph":"(273) 886-6244","sups":['JOSEPH CLARK', 'MICHAEL CLARK', 'KAREN RODRIGUEZ']},
    {"name":"PATRIOT LAKESIDE FREIGHTWAYS GROUP LLC","addr":"1799 Fleet St, SPOKANE, WA 68310","dot":"558036","ph":"(402) 757-9164","sups":['LINDA RAMIREZ', 'ANTONIO BROWN', 'SOFIA LOPEZ']},
    {"name":"HAWK FREIGHT SYSTEMS CO","addr":"3809 Highway Dr, FORT WORTH, TX 11553","dot":"3456510","ph":"(627) 278-2472","sups":['CARLOS THOMAS', 'ANA LEE', 'JOSE MILLER']},
    {"name":"CARGO PLAINS SHIPPING INC","addr":"3925 Northgate Blvd, CHICAGO, IL 36867","dot":"824302","ph":"(221) 563-9842","sups":['MICHAEL LOPEZ', 'ANA TAYLOR', 'DIANA RODRIGUEZ']},
    {"name":"FREIGHT TRANSPORT LLC LP","addr":"5650 Depot St, DES MOINES, IA 16571","dot":"1950752","ph":"(839) 727-2706","sups":['SUSAN RODRIGUEZ', 'SOFIA BROWN', 'ANA GONZALEZ']},
    {"name":"DESERT LOGISTICS LLC CORP","addr":"712 Highway Dr, EL PASO, TX 37465","dot":"2276749","ph":"(608) 989-6459","sups":['JOSEPH LEWIS', 'CHARLES LEE', 'ANA MARTIN']},
    {"name":"PACIFIC MOUNTAIN EXPRESS LP","addr":"4800 Depot St, BOISE, ID 13760","dot":"2067978","ph":"(503) 970-5331","sups":['LINDA MARTINEZ', 'MICHAEL HARRIS', 'MARIA WILSON']},
    {"name":"THOMPSON TRUCKING ENTERPRISES LLC","addr":"6799 Fleet St, AUSTIN, TX 23943","dot":"1492640","ph":"(936) 340-8318","sups":['ANTONIO ROBINSON', 'MICHAEL LEWIS', 'SARAH JACKSON']},
    {"name":"DAVIS LINES ENTERPRISES LLC","addr":"1187 Industrial Way, DALLAS, TX 95903","dot":"774534","ph":"(607) 263-6728","sups":['SOFIA HERNANDEZ', 'WILLIAM LEWIS', 'MARY MARTIN']},
    {"name":"JACKSON LOGISTICS LLC INC","addr":"4997 Cargo Way, LITTLE ROCK, AR 88839","dot":"805948","ph":"(784) 418-5573","sups":['DIANA WHITE', 'LINDA RAMIREZ', 'WILLIAM DAVIS']},
    {"name":"MIDWEST LOGISTICS LLC HOLDINGS INC","addr":"2483 Corporate Dr, BATON ROUGE, LA 21081","dot":"3447040","ph":"(322) 979-8176","sups":['WILLIAM BROWN', 'PATRICIA DAVIS', 'DAVID HARRIS']},
    {"name":"ROBINSON TRANSPORT SERVICES CO","addr":"6253 Airport Rd, DALLAS, TX 49842","dot":"1211436","ph":"(627) 282-5296","sups":['THOMAS DAVIS', 'RICHARD TAYLOR', 'LINDA JONES']},
    {"name":"PACIFIC TRUCKING CO CORP","addr":"4718 Fleet St, JOPLIN, MO 84805","dot":"1987249","ph":"(233) 330-3996","sups":['DAVID MARTIN', 'RICHARD GONZALEZ', 'MARIA TAYLOR']},
    {"name":"XPO MOUNTAIN LOGISTICS LLC HOLDINGS INC","addr":"7362 Depot St, BATON ROUGE, LA 44900","dot":"1116671","ph":"(509) 633-7596","sups":['LAURA RAMIREZ', 'MARIA JOHNSON', 'JAMES THOMPSON']},
    {"name":"LEGACY TRUCKING INC","addr":"9395 Fleet St, LUBBOCK, TX 16322","dot":"786928","ph":"(557) 673-7535","sups":['JOHN HERNANDEZ', 'JOHN HARRIS', 'THOMAS PEREZ']},
    {"name":"IRON FREIGHT SYSTEMS CORP","addr":"2448 Fleet St, DES MOINES, IA 94500","dot":"3321738","ph":"(770) 564-8049","sups":['CHARLES LEE', 'LUIS RAMIREZ', 'WILLIAM RODRIGUEZ']},
    {"name":"HEARTLAND LAKESIDE CARRIERS INC","addr":"7923 Trucking Ln, COLUMBIA, SC 32363","dot":"3581670","ph":"(829) 860-1766","sups":['JESSICA MARTINEZ', 'LUIS WHITE', 'THOMAS JONES']},
    {"name":"COASTAL TRUCKING CO INC","addr":"701 Cargo Way, HOUSTON, TX 29013","dot":"3604166","ph":"(895) 928-5458","sups":['JOHN MOORE', 'MIGUEL PEREZ', 'ROBERT RAMIREZ']},
    {"name":"WERNER CARRIERS INC GROUP LLC","addr":"6522 Fleet St, EVANSVILLE, IN 37727","dot":"3633677","ph":"(350) 653-5642","sups":['LAURA WHITE', 'JOHN LEE', 'SUSAN MILLER']},
    {"name":"ROEHL SILVER TRANSPORT SERVICES LLC","addr":"8689 Industrial Way, EVANSVILLE, IN 95646","dot":"3393446","ph":"(257) 447-6543","sups":['DIANA ROBINSON', 'SUSAN BROWN', 'JENNIFER WHITE']},
    {"name":"HEARTLAND EXPRESS GROUP LLC","addr":"643 Cargo Way, LANSING, MI 39644","dot":"1002093","ph":"(900) 815-7673","sups":['DIANA JOHNSON', 'CHARLES CLARK', 'SARAH MILLER']},
    {"name":"SCHNEIDER FREIGHT ENTERPRISES LLC","addr":"9784 Business Center Dr, DALLAS, TX 28688","dot":"2904973","ph":"(894) 981-2579","sups":['JAMES RAMIREZ', 'MICHAEL SMITH', 'DIANA SANCHEZ']},
    {"name":"COASTAL TRANSPORT LLC CORP","addr":"944 Highway Dr, LOUISVILLE, KY 99730","dot":"1283128","ph":"(681) 415-1316","sups":['JENNIFER WILSON', 'MARIA BROWN', 'ELIZABETH LOPEZ']},
    {"name":"TRANS TRUCKING CO HOLDINGS INC","addr":"6770 Highway Dr, MEMPHIS, TN 50896","dot":"2243650","ph":"(296) 701-2877","sups":['SARAH JOHNSON', 'BARBARA THOMPSON', 'JESSICA WILLIAMS']},
    {"name":"PEREZ LOGISTICS INC","addr":"9358 Highway Dr, CHATTANOOGA, TN 49166","dot":"3891908","ph":"(657) 519-7023","sups":['ANA JONES', 'CHARLES DAVIS', 'JAMES WHITE']},
    {"name":"ATLANTIC SHIPPING LLC","addr":"6341 Northgate Blvd, LAREDO, TX 42212","dot":"3967854","ph":"(809) 782-1474","sups":['SOFIA BROWN', 'SUSAN THOMPSON', 'KAREN WILLIAMS']},
    {"name":"JB HUNT TRUCKING CO GROUP LLC","addr":"8106 Business Center Dr, JOPLIN, MO 61133","dot":"3665686","ph":"(854) 776-6661","sups":['KAREN BROWN', 'BARBARA GONZALEZ', 'MICHAEL LEWIS']},
    {"name":"APEX LIBERTY BELL CARRIERS INC ENTERPRISES LLC","addr":"1476 Trucking Ln, FORT WORTH, TX 45293","dot":"839533","ph":"(660) 256-5860","sups":['LINDA RODRIGUEZ', 'CHARLES MOORE', 'PATRICIA RODRIGUEZ']},
    {"name":"CARGO LOGISTICS HOLDINGS INC","addr":"3407 Westside Dr, COLUMBIA, SC 99245","dot":"3885665","ph":"(495) 979-2633","sups":['DIANA GARCIA', 'WILLIAM HARRIS', 'KAREN BROWN']},
    {"name":"HEARTLAND UNITED TRANSPORT INC","addr":"4782 Airport Rd, FRESNO, CA 41335","dot":"2633738","ph":"(759) 999-5937","sups":['DAVID HERNANDEZ', 'JAMES BROWN', 'PATRICIA BROWN']},
    {"name":"BIG RIG LOGISTICS INC","addr":"4910 Logistics Blvd, AMARILLO, TX 38650","dot":"771267","ph":"(291) 794-8208","sups":['JOSEPH GONZALEZ', 'LUIS JONES', 'ANA MOORE']},
    {"name":"JACKSON LOGISTICS ENTERPRISES LLC","addr":"2906 Terminal Rd, FORT WORTH, TX 47369","dot":"890935","ph":"(377) 350-2624","sups":['LINDA DAVIS', 'ROBERT MARTINEZ', 'DIANA SANCHEZ']},
    {"name":"PEREZ TRUCKING CORP","addr":"1574 Park Ave, SHREVEPORT, LA 86211","dot":"1628726","ph":"(400) 620-1533","sups":['MARIA MILLER', 'ELIZABETH RAMIREZ', 'BARBARA MARTIN']},
    {"name":"SILVER TRUCKING LP","addr":"4984 Airport Rd, PHOENIX, AZ 30755","dot":"1525381","ph":"(363) 970-7127","sups":['JOHN JACKSON', 'MARY RAMIREZ', 'MARIA MARTINEZ']},
    {"name":"WERNER FREIGHTWAYS ENTERPRISES LLC","addr":"5657 Logistics Blvd, FORT WORTH, TX 84591","dot":"118407","ph":"(515) 807-3783","sups":['MARY JOHNSON', 'ANTONIO ROBINSON', 'LINDA MARTINEZ']},
    {"name":"LEGACY FREIGHT SYSTEMS GROUP LLC","addr":"8562 Terminal Rd, PHOENIX, AZ 71290","dot":"2983912","ph":"(547) 455-6123","sups":['SUSAN THOMAS', 'JAMES LEWIS', 'JOHN SMITH']},
    {"name":"FREEDOM EXPRESS HOLDINGS INC","addr":"4167 Terminal Rd, CHICAGO, IL 92000","dot":"1320854","ph":"(443) 411-5655","sups":['JOSE BROWN', 'JOHN CLARK', 'RICHARD CLARK']},
    {"name":"ESTES SHIPPING CORP","addr":"7638 Enterprise Way, GRAND RAPIDS, MI 17672","dot":"3353984","ph":"(843) 859-2236","sups":['MIGUEL WILSON', 'JOSE ROBINSON', 'ROBERT BROWN']},
    {"name":"DIAMOND TRUCKING CO INC","addr":"759 Logistics Blvd, MILWAUKEE, WI 95270","dot":"2170646","ph":"(255) 390-7928","sups":['PATRICIA RAMIREZ', 'JOSE LEE', 'LAURA JOHNSON']},
    {"name":"NORTHERN TRUCKING LLC","addr":"8800 Industrial Way, LOUISVILLE, KY 47995","dot":"1190823","ph":"(946) 810-6743","sups":['CARLOS WHITE', 'JOSE WILSON', 'SUSAN MARTIN']},
    {"name":"SYNERGY FRONTIER LOGISTICS GROUP LLC","addr":"206 Terminal Rd, ATLANTA, GA 60445","dot":"3608890","ph":"(596) 767-8221","sups":['LINDA HERNANDEZ', 'ROBERT RAMIREZ', 'ANTONIO LEWIS']},
    {"name":"MOUNTAIN HEARTLAND TRANSPORT LP","addr":"7863 Logistics Blvd, NASHVILLE, TN 93832","dot":"930947","ph":"(649) 217-7815","sups":['ROBERT JOHNSON', 'ROBERT GONZALEZ', 'ANA THOMPSON']},
    {"name":"LAKESIDE FREIGHTWAYS LLC","addr":"2746 Corporate Dr, DAYTON, OH 73757","dot":"1872439","ph":"(517) 747-7118","sups":['JAMES ROBINSON', 'PATRICIA GONZALEZ', 'BARBARA JACKSON']},
    {"name":"TURNPIKE FREIGHT SYSTEMS GROUP LLC","addr":"6726 Park Ave, SAN ANTONIO, TX 13538","dot":"2777378","ph":"(431) 922-3259","sups":['DIANA THOMAS', 'JESSICA LOPEZ', 'LAURA GARCIA']},
    {"name":"HEARTLAND FREIGHTWAYS INC","addr":"3998 Freight Way, SAN ANTONIO, TX 89580","dot":"2693346","ph":"(540) 271-8885","sups":['RICHARD WHITE', 'CARLOS DAVIS', 'KAREN CLARK']},
    {"name":"ROBINSON FREIGHTWAYS CORP","addr":"8238 Airport Rd, AUSTIN, TX 13588","dot":"3555542","ph":"(490) 235-2904","sups":['LINDA WILLIAMS', 'JENNIFER JACKSON', 'LINDA MILLER']},
    {"name":"ANDERSON CARRIERS CORP","addr":"1656 Logistics Blvd, KANSAS CITY, MO 29723","dot":"602767","ph":"(758) 667-7337","sups":['JESSICA RODRIGUEZ', 'ANA HERNANDEZ', 'BARBARA ROBINSON']},
    {"name":"EASTERN ROYAL LOGISTICS LLC LP","addr":"598 Enterprise Way, MOBILE, AL 59282","dot":"2253184","ph":"(810) 273-1106","sups":['SOFIA DAVIS', 'PATRICIA SMITH', 'BARBARA PEREZ']},
    {"name":"WILSON FREIGHT SYSTEMS HOLDINGS INC","addr":"8104 Enterprise Way, TOLEDO, OH 96180","dot":"3967016","ph":"(602) 291-8388","sups":['LUIS SMITH', 'SOFIA SMITH', 'BARBARA THOMPSON']},
    {"name":"MARTEN HAULING GROUP LLC","addr":"970 Trucking Ln, LANSING, MI 17042","dot":"3811462","ph":"(302) 645-4824","sups":['ROBERT BROWN', 'LUIS DAVIS', 'ANTONIO JONES']},
    {"name":"EAGLE EASTERN HAULING HOLDINGS INC","addr":"2040 Broad St, ATLANTA, GA 47846","dot":"3915901","ph":"(572) 971-6539","sups":['BARBARA JOHNSON', 'WILLIAM ROBINSON', 'WILLIAM HARRIS']},
    {"name":"THOMAS LOGISTICS GROUP CO","addr":"9421 Westside Dr, CHICAGO, IL 67641","dot":"2361832","ph":"(475) 562-6735","sups":['LAURA TAYLOR', 'LAURA ROBINSON', 'MICHAEL HERNANDEZ']},
    {"name":"USA SHIPPING CO","addr":"5958 Depot St, MINNEAPOLIS, MN 46914","dot":"2193365","ph":"(449) 275-9684","sups":['MICHAEL RODRIGUEZ', 'CARLOS PEREZ', 'CARLOS RODRIGUEZ']},
    {"name":"LEE TRANSPORT HOLDINGS INC","addr":"6121 Distribution Center Rd, PORTLAND, OR 52085","dot":"2372698","ph":"(397) 539-4236","sups":['CHARLES WHITE', 'CARLOS RODRIGUEZ', 'ANTONIO JACKSON']},
    {"name":"ROYAL HAULING HOLDINGS INC","addr":"4931 Airport Rd, TULSA, OK 88218","dot":"100301","ph":"(494) 531-1799","sups":['JAMES MARTINEZ', 'DAVID GARCIA', 'JESSICA RAMIREZ']},
    {"name":"PINNACLE TRUCKING CO LP","addr":"7061 Northgate Blvd, JOPLIN, MO 62467","dot":"2427235","ph":"(792) 553-2849","sups":['LUIS JOHNSON', 'SARAH ANDERSON', 'THOMAS CLARK']},
    {"name":"WILLIAMS TRUCKING CO GROUP LLC","addr":"6850 Logistics Blvd, MEMPHIS, TN 78097","dot":"3533912","ph":"(419) 642-6910","sups":['JAMES ANDERSON', 'ROBERT HERNANDEZ', 'DIANA RAMIREZ']},
    {"name":"SCHNEIDER LOGISTICS LLC LP","addr":"3010 Logistics Blvd, PHOENIX, AZ 99122","dot":"3451246","ph":"(881) 740-3473","sups":['LUIS WILSON', 'PATRICIA ROBINSON', 'JESSICA RAMIREZ']},
    {"name":"PHOENIX LOGISTICS ENTERPRISES LLC","addr":"6295 Cargo Way, CHATTANOOGA, TN 87838","dot":"729321","ph":"(674) 578-9670","sups":['JOSEPH LOPEZ', 'JAMES SMITH', 'BARBARA RAMIREZ']},
    {"name":"THOMPSON FREIGHTWAYS LLC","addr":"6684 Highway Dr, RICHMOND, VA 92076","dot":"3192382","ph":"(908) 310-5496","sups":['THOMAS WILSON', 'ELIZABETH LEE', 'LUIS LOPEZ']},
    {"name":"CARGO EASTERN EXPRESS GROUP LLC","addr":"8008 Industrial Way, SPRINGFIELD, MO 93142","dot":"3598919","ph":"(908) 736-1942","sups":['MICHAEL WHITE', 'JENNIFER LOPEZ', 'JOSEPH WILSON']},
    {"name":"CATALYST SHIPPING ENTERPRISES LLC","addr":"9158 Fleet St, MCALLEN, TX 85099","dot":"1638697","ph":"(486) 548-9079","sups":['SARAH RAMIREZ', 'SOFIA HERNANDEZ', 'JOHN HARRIS']},
    {"name":"CARGO MASTER TRANSPORT HOLDINGS INC","addr":"8240 Southpoint Dr, LAREDO, TX 24519","dot":"1965419","ph":"(799) 750-5899","sups":['CARLOS WHITE', 'ELIZABETH GONZALEZ', 'CARLOS LOPEZ']},
    {"name":"AMERICAN FREIGHT SYSTEMS LLC","addr":"8022 Westside Dr, BATON ROUGE, LA 43286","dot":"3944762","ph":"(518) 315-6615","sups":['MIGUEL RODRIGUEZ', 'ANTONIO MOORE', 'ANA RAMIREZ']},
    {"name":"MARTEN TRUCKING CO LP","addr":"5903 Industrial Pkwy, MONTGOMERY, AL 79523","dot":"3560607","ph":"(296) 349-5034","sups":['SOFIA SANCHEZ', 'MARY THOMAS', 'PATRICIA SMITH']},
    {"name":"LIBERTY BELL TRANSPORT SERVICES ENTERPRISES LLC","addr":"7879 Trucking Ln, LAS VEGAS, NV 26887","dot":"3035555","ph":"(457) 430-2989","sups":['JESSICA ANDERSON', 'DIANA RODRIGUEZ', 'JESSICA GARCIA']},
    {"name":"PACIFIC CARRIERS GROUP LLC","addr":"9311 Terminal Rd, SPRINGFIELD, MO 60841","dot":"1595222","ph":"(685) 337-1739","sups":['JAMES JACKSON', 'SOFIA RODRIGUEZ', 'JOHN RODRIGUEZ']},
    {"name":"EXPRESS FREIGHTWAYS CO","addr":"5077 Commerce Dr, FORT WAYNE, IN 37234","dot":"3505497","ph":"(918) 676-2090","sups":['BARBARA MARTIN', 'MARIA JACKSON', 'THOMAS LEE']},
    {"name":"COAST TO COAST TRUCKING CO ENTERPRISES LLC","addr":"2985 Main St, EL PASO, TX 91505","dot":"1176103","ph":"(442) 905-6909","sups":['ELIZABETH BROWN', 'LINDA MARTIN', 'LUIS WILSON']},
    {"name":"UNITED TRUCKING ENTERPRISES LLC","addr":"6415 Westside Dr, LITTLE ROCK, AR 53356","dot":"2148719","ph":"(988) 578-9366","sups":['ANTONIO JONES', 'SUSAN MOORE', 'BARBARA RODRIGUEZ']},
    {"name":"HEARTLAND LOGISTICS HOLDINGS INC","addr":"4999 Trucking Ln, SHREVEPORT, LA 35364","dot":"3359388","ph":"(588) 363-7479","sups":['MICHAEL PEREZ', 'MARY THOMAS', 'THOMAS RODRIGUEZ']},
    {"name":"PLATINUM HAULING ENTERPRISES LLC","addr":"3149 Corporate Dr, SAN ANTONIO, TX 95568","dot":"1684989","ph":"(227) 276-7780","sups":['WILLIAM THOMPSON', 'DIANA RODRIGUEZ', 'SARAH SANCHEZ']},
    {"name":"JB HUNT CARRIERS INC ENTERPRISES LLC","addr":"5644 Fleet St, HOUSTON, TX 27760","dot":"3049876","ph":"(693) 991-6137","sups":['PATRICIA GONZALEZ', 'LINDA GARCIA', 'MARIA MARTIN']},
    {"name":"CARGO MASTER CARGO TRANSPORT LLC LLC","addr":"6860 Highway Dr, AMARILLO, TX 51884","dot":"3219837","ph":"(868) 208-9037","sups":['ROBERT JOHNSON', 'ANTONIO DAVIS', 'BARBARA HERNANDEZ']},
    {"name":"INDEPENDENCE FREIGHT CO","addr":"116 Airport Rd, LAREDO, TX 36413","dot":"1160477","ph":"(292) 846-8432","sups":['ELIZABETH PEREZ', 'KAREN MARTINEZ', 'RICHARD SMITH']},
    {"name":"MARTINEZ HAULING CORP","addr":"7831 Main St, MONTGOMERY, AL 62885","dot":"2870422","ph":"(245) 581-1276","sups":['PATRICIA DAVIS', 'DAVID HERNANDEZ', 'SARAH LOPEZ']},
    {"name":"JACKSON FREIGHTWAYS ENTERPRISES LLC","addr":"794 Trucking Ln, MILWAUKEE, WI 64111","dot":"321101","ph":"(395) 448-4594","sups":['CARLOS JONES', 'ANA GARCIA', 'PATRICIA LEWIS']},
    {"name":"TRAIL BLAZER FREIGHTWAYS LLC","addr":"6969 Cargo Way, FRESNO, CA 56969","dot":"2410140","ph":"(373) 493-9391","sups":['WILLIAM JOHNSON', 'JOSE GARCIA', 'MIGUEL JONES']},
    {"name":"AMERICAN TRANSPORTATION CO","addr":"3957 Distribution Center Rd, EVANSVILLE, IN 68502","dot":"3015360","ph":"(547) 674-6632","sups":['ANA DAVIS', 'MARY BROWN', 'JESSICA LEE']},
    {"name":"SILVER SILVER SHIPPING INC","addr":"4174 Cargo Way, MILWAUKEE, WI 12396","dot":"3372570","ph":"(387) 707-6947","sups":['RICHARD JONES', 'MIGUEL CLARK', 'WILLIAM RAMIREZ']},
    {"name":"ROBINSON TRANSPORTATION INC","addr":"4872 Industrial Way, SPOKANE, WA 54082","dot":"2364339","ph":"(822) 220-7598","sups":['MARIA JACKSON', 'PATRICIA GONZALEZ', 'WILLIAM RAMIREZ']},
    {"name":"VANGUARD PIONEER TRUCKING CO CORP","addr":"9950 Logistics Blvd, LANSING, MI 74581","dot":"2175195","ph":"(340) 896-4488","sups":['CHARLES LEE', 'JOSE RAMIREZ', 'JESSICA LEE']},
    {"name":"FALCON FREIGHT CORP","addr":"1616 Corporate Dr, LOUISVILLE, KY 35150","dot":"1454797","ph":"(906) 561-2046","sups":['JENNIFER DAVIS', 'JAMES DAVIS', 'LINDA PEREZ']},
    {"name":"WILSON LOGISTICS CORP","addr":"5886 Airport Rd, MINNEAPOLIS, MN 94757","dot":"2716236","ph":"(621) 566-2378","sups":['JENNIFER RAMIREZ', 'MARIA CLARK', 'THOMAS GONZALEZ']},
    {"name":"FREIGHT LOGISTICS LLC CORP","addr":"4039 Freight Way, SHREVEPORT, LA 90984","dot":"260966","ph":"(301) 369-2698","sups":['MARIA PEREZ', 'MIGUEL TAYLOR', 'ROBERT RODRIGUEZ']},
    {"name":"LEGACY CARRIERS INC","addr":"5491 Airport Rd, MEMPHIS, TN 17344","dot":"3991163","ph":"(808) 756-3705","sups":['LAURA MARTIN', 'JOHN LEE', 'MICHAEL JONES']},
    {"name":"JONES TRUCKING GROUP LLC","addr":"9768 Freight Way, AKRON, OH 36153","dot":"2244511","ph":"(526) 477-3421","sups":['RICHARD MILLER', 'JAMES GONZALEZ', 'PATRICIA SANCHEZ']},
    {"name":"MILLER TRANSPORTATION HOLDINGS INC","addr":"399 Logistics Blvd, SALT LAKE CITY, UT 28274","dot":"1362136","ph":"(274) 702-8949","sups":['THOMAS JACKSON', 'SUSAN RAMIREZ', 'BARBARA WILSON']},
    {"name":"MIDWEST SYNERGY FREIGHTWAYS LP","addr":"6051 Fleet St, OMAHA, NE 74047","dot":"1276514","ph":"(502) 507-1613","sups":['JENNIFER MOORE', 'SOFIA SANCHEZ', 'JOSE ANDERSON']},
    {"name":"THOMAS TRANSPORT INC","addr":"2219 Terminal Rd, LOUISVILLE, KY 47543","dot":"1577733","ph":"(527) 822-3031","sups":['ANTONIO SMITH', 'PATRICIA THOMAS', 'LAURA JACKSON']},
    {"name":"WILLIAMS CARRIERS INC HOLDINGS INC","addr":"6962 Fleet St, CORPUS CHRISTI, TX 84749","dot":"3131214","ph":"(695) 793-3233","sups":['SOFIA ROBINSON', 'DAVID RAMIREZ', 'WILLIAM JONES']},
    {"name":"MARTEN PLATINUM LOGISTICS LLC INC","addr":"1795 Eastgate Dr, GRAND RAPIDS, MI 90216","dot":"1884011","ph":"(609) 963-7091","sups":['MARIA TAYLOR', 'RICHARD LEWIS', 'DIANA GONZALEZ']},
    {"name":"STAR STERLING CARRIERS CO","addr":"7586 Cargo Way, COLUMBIA, SC 87534","dot":"3320632","ph":"(952) 768-3324","sups":['ELIZABETH SANCHEZ', 'MICHAEL TAYLOR', 'WILLIAM BROWN']},
    {"name":"MIDWEST ROYAL TRANSPORT LLC ENTERPRISES LLC","addr":"5202 Southpoint Dr, LAS VEGAS, NV 96627","dot":"1085834","ph":"(559) 612-6158","sups":['ROBERT JOHNSON', 'WILLIAM MARTINEZ', 'BARBARA LEWIS']},
    {"name":"HIGHWAY TRUCKING INC","addr":"9032 Main St, LANSING, MI 68659","dot":"2453853","ph":"(863) 659-3457","sups":['SOFIA CLARK', 'JAMES GONZALEZ', 'ROBERT MARTIN']},
    {"name":"BLUE SKY TRAIL BLAZER TRUCKING INC","addr":"4729 Broad St, AMARILLO, TX 55161","dot":"3260642","ph":"(485) 855-2434","sups":['RICHARD LEWIS', 'LAURA DAVIS', 'SARAH WHITE']},
    {"name":"CATALYST COAST TO COAST TRANSPORT SERVICES HOLDINGS INC","addr":"5712 Westside Dr, FORT WORTH, TX 21146","dot":"537038","ph":"(553) 252-3731","sups":['KAREN RODRIGUEZ', 'BARBARA HARRIS', 'JOSEPH DAVIS']},
    {"name":"SYNERGY FREIGHT CORP","addr":"2803 Corporate Dr, MOBILE, AL 47888","dot":"437184","ph":"(463) 985-5641","sups":['LUIS BROWN', 'ROBERT SANCHEZ', 'ANA JOHNSON']},
    {"name":"DIAMOND LOGISTICS LLC LP","addr":"394 Airport Rd, DES MOINES, IA 55456","dot":"2517022","ph":"(797) 774-3920","sups":['SARAH ROBINSON', 'KAREN BROWN', 'JENNIFER CLARK']},
    {"name":"COAST TO COAST TRANSPORT CORP","addr":"4382 Northgate Blvd, CHICAGO, IL 58817","dot":"2719035","ph":"(361) 444-8152","sups":['JOSE ANDERSON', 'SUSAN THOMPSON', 'JESSICA MOORE']},
    {"name":"WILSON TRUCKING CO GROUP LLC","addr":"5754 Main St, LANSING, MI 89804","dot":"2154802","ph":"(728) 999-8039","sups":['MARIA DAVIS', 'MIGUEL CLARK', 'JOSEPH RAMIREZ']},
    {"name":"MIDWEST TRANS CARRIERS INC ENTERPRISES LLC","addr":"9950 Freight Way, HOUSTON, TX 92384","dot":"2107823","ph":"(676) 390-1884","sups":['SOFIA SANCHEZ', 'MARIA PEREZ', 'JOHN ANDERSON']},
    {"name":"LEGACY TRUCKING CO CO","addr":"3297 Westside Dr, MOBILE, AL 99896","dot":"1248088","ph":"(947) 327-2837","sups":['ELIZABETH LEE', 'WILLIAM RAMIREZ', 'LAURA CLARK']},
    {"name":"APEX ALL AMERICAN LOGISTICS LP","addr":"7136 Park Ave, SAN ANTONIO, TX 52550","dot":"2957518","ph":"(867) 360-8871","sups":['ANTONIO THOMAS', 'JOSEPH LEE', 'SARAH ROBINSON']},
    {"name":"ROEHL PATRIOT TRUCKING HOLDINGS INC","addr":"6575 Industrial Way, DENVER, CO 17085","dot":"3465145","ph":"(340) 411-2674","sups":['PATRICIA HARRIS', 'DIANA THOMPSON', 'ROBERT MARTINEZ']},
    {"name":"LOPEZ TRUCKING HOLDINGS INC","addr":"3672 Airport Rd, GREENSBORO, NC 91073","dot":"926372","ph":"(599) 252-3071","sups":['SUSAN RAMIREZ', 'ANTONIO LEE', 'CARLOS JONES']},
    {"name":"MOMENTUM CARRIERS INC HOLDINGS INC","addr":"6307 Highway Dr, DALLAS, TX 17508","dot":"3519179","ph":"(811) 640-5312","sups":['JESSICA SMITH', 'RICHARD WHITE', 'LAURA MARTINEZ']},
    {"name":"KNIGHT RED RIVER FREIGHT SYSTEMS LLC","addr":"7083 Industrial Way, MONTGOMERY, AL 66197","dot":"3303219","ph":"(223) 893-5362","sups":['SOFIA JOHNSON', 'ELIZABETH JACKSON', 'SOFIA RODRIGUEZ']},
    {"name":"FRONTIER ESTES FREIGHT SYSTEMS GROUP LLC","addr":"8354 Eastgate Dr, OMAHA, NE 33632","dot":"1664688","ph":"(712) 557-8464","sups":['KAREN ANDERSON', 'JENNIFER MARTIN', 'JAMES MARTINEZ']},
    {"name":"VANGUARD NORTHERN CARRIERS INC LP","addr":"9024 Terminal Rd, RENO, NV 95755","dot":"1343418","ph":"(263) 562-7047","sups":['JESSICA RODRIGUEZ', 'ANA MILLER', 'MARY PEREZ']},
    {"name":"HIGHWAY CARRIERS INC CORP","addr":"7989 Industrial Pkwy, DES MOINES, IA 69251","dot":"1483452","ph":"(700) 497-9246","sups":['JAMES HERNANDEZ', 'ANTONIO MARTINEZ', 'LINDA SMITH']},
    {"name":"ROEHL TRUCKING CO CORP","addr":"3800 Enterprise Way, HOUSTON, TX 56160","dot":"1864626","ph":"(857) 689-3659","sups":['MARIA MARTINEZ', 'ROBERT ROBINSON', 'ROBERT MARTIN']},
    {"name":"GREEN VALLEY TRANSPORT CO","addr":"9418 Northgate Blvd, LANSING, MI 67203","dot":"1649094","ph":"(949) 689-5252","sups":['CHARLES ROBINSON', 'MARIA HARRIS', 'LAURA PEREZ']},
    {"name":"LAKESIDE TRANS LOGISTICS GROUP LLC","addr":"5957 Westside Dr, CORPUS CHRISTI, TX 25219","dot":"2223283","ph":"(423) 502-6695","sups":['ROBERT LEE', 'JENNIFER WILSON', 'CHARLES DAVIS']},
    {"name":"BIG RIG TRANSPORT SERVICES CORP","addr":"6266 Eastgate Dr, WICHITA, KS 13316","dot":"3588514","ph":"(757) 896-8250","sups":['MARIA ANDERSON', 'JOSE WHITE', 'CARLOS SMITH']},
    {"name":"ROYAL DIAMOND TRANSPORT SERVICES CORP","addr":"6687 Broad St, SAN ANTONIO, TX 32719","dot":"1054495","ph":"(260) 725-7591","sups":['THOMAS HERNANDEZ', 'JOHN GARCIA', 'BARBARA LEWIS']},
    {"name":"COAST TO COAST TRUCKING CO HOLDINGS INC","addr":"4537 Industrial Way, SEATTLE, WA 88442","dot":"668012","ph":"(850) 770-5835","sups":['PATRICIA LOPEZ', 'JENNIFER MARTINEZ', 'LINDA GARCIA']},
    {"name":"PACIFIC FREIGHT SYSTEMS HOLDINGS INC","addr":"1942 Southpoint Dr, DAYTON, OH 63518","dot":"2584598","ph":"(820) 522-7603","sups":['RICHARD WILSON', 'SUSAN CLARK', 'RICHARD JONES']},
    {"name":"GARCIA LINES LP","addr":"7711 Main St, RENO, NV 17573","dot":"1778689","ph":"(771) 845-6503","sups":['CARLOS JONES', 'KAREN MOORE', 'WILLIAM LOPEZ']},
    {"name":"DIAMOND CARRIERS INC ENTERPRISES LLC","addr":"2756 Logistics Blvd, COLUMBIA, SC 76189","dot":"570361","ph":"(288) 864-3878","sups":['CARLOS GONZALEZ', 'LINDA MARTINEZ', 'CARLOS BROWN']},
    {"name":"SILVER LINES LLC","addr":"1399 Cargo Way, SHREVEPORT, LA 50676","dot":"2512870","ph":"(797) 703-2415","sups":['CARLOS WILSON', 'PATRICIA GONZALEZ', 'MICHAEL DAVIS']},
    {"name":"JB HUNT HAULING LP","addr":"7871 Main St, JACKSON, MS 90505","dot":"1067725","ph":"(201) 226-3372","sups":['DIANA CLARK', 'MIGUEL LEE', 'JESSICA SMITH']},
    {"name":"FOUNDERS ROAD KING EXPRESS ENTERPRISES LLC","addr":"8791 Broad St, KANSAS CITY, MO 44458","dot":"1329033","ph":"(351) 734-4457","sups":['PATRICIA WILLIAMS', 'MARIA DAVIS', 'CARLOS LOPEZ']},
    {"name":"PEREZ TRANSPORT LLC HOLDINGS INC","addr":"9371 Enterprise Way, LITTLE ROCK, AR 23998","dot":"386954","ph":"(369) 499-8864","sups":['JESSICA RODRIGUEZ', 'KAREN GONZALEZ', 'BARBARA TAYLOR']},
    {"name":"CONTINENTAL TRUCKING INC","addr":"9420 Industrial Pkwy, JACKSON, MS 53117","dot":"1337683","ph":"(445) 846-3485","sups":['JOHN DAVIS', 'MIGUEL WILLIAMS', 'SOFIA SANCHEZ']},
    {"name":"MARTIN TRUCKING CO","addr":"6928 Commerce Dr, SAN ANTONIO, TX 80938","dot":"1608561","ph":"(966) 520-2767","sups":['RICHARD MARTIN', 'LINDA BROWN', 'DIANA ANDERSON']},
    {"name":"INDEPENDENCE LOGISTICS ENTERPRISES LLC","addr":"4202 Eastgate Dr, BAKERSFIELD, CA 49783","dot":"279423","ph":"(813) 952-5532","sups":['SOFIA TAYLOR', 'MIGUEL LEE', 'ROBERT LEE']},
    {"name":"USA XPO LINES LLC","addr":"4557 Trucking Ln, SAN ANTONIO, TX 66543","dot":"3882502","ph":"(698) 634-7898","sups":['LUIS WILSON', 'ANA WILSON', 'KAREN JOHNSON']},
    {"name":"VANGUARD CATALYST CARRIERS INC INC","addr":"1655 Northgate Blvd, CORPUS CHRISTI, TX 33903","dot":"279196","ph":"(884) 374-3974","sups":['MARIA CLARK', 'SUSAN CLARK', 'DAVID GONZALEZ']},
    {"name":"MIDWEST TRANSPORT GROUP LLC","addr":"286 Industrial Way, EVANSVILLE, IN 95512","dot":"3117980","ph":"(577) 479-9708","sups":['ANTONIO THOMPSON', 'RICHARD RAMIREZ', 'MARY THOMAS']},
    {"name":"PLATINUM LOGISTICS ENTERPRISES LLC","addr":"4288 Airport Rd, CHICAGO, IL 61774","dot":"2096205","ph":"(237) 200-3092","sups":['LUIS MILLER', 'THOMAS WHITE', 'PATRICIA LEE']},
    {"name":"BLUE SKY CARGO MASTER EXPRESS LLC","addr":"1479 Distribution Center Rd, WICHITA, KS 26950","dot":"3776070","ph":"(341) 217-8723","sups":['RICHARD LOPEZ', 'SUSAN LEE', 'MARY GONZALEZ']},
    {"name":"THOMAS LOGISTICS GROUP ENTERPRISES LLC","addr":"9186 Commerce Dr, MEMPHIS, TN 46463","dot":"3018346","ph":"(949) 835-5631","sups":['BARBARA GARCIA', 'WILLIAM SMITH', 'KAREN SMITH']},
    {"name":"PHOENIX FREIGHT CO","addr":"9697 Airport Rd, AKRON, OH 72601","dot":"2704364","ph":"(738) 781-9841","sups":['SOFIA GONZALEZ', 'MIGUEL SMITH', 'LINDA LEE']},
    {"name":"VELOCITY DIAMOND LINES CORP","addr":"1637 Southpoint Dr, LANSING, MI 38424","dot":"3969776","ph":"(609) 856-4471","sups":['MARY MARTIN', 'LAURA HERNANDEZ', 'ROBERT THOMPSON']},
    {"name":"DESERT XPO EXPRESS CO","addr":"4414 Depot St, CHARLOTTE, NC 52538","dot":"1524283","ph":"(613) 482-9080","sups":['SOFIA RAMIREZ', 'DIANA MOORE', 'JOHN PEREZ']},
    {"name":"HEARTLAND HAWK FREIGHT SYSTEMS INC","addr":"9068 Business Center Dr, INDIANAPOLIS, IN 28914","dot":"2580124","ph":"(962) 687-6258","sups":['KAREN HARRIS', 'SARAH LEWIS', 'ROBERT LEE']},
    {"name":"UNITED LOGISTICS LLC INC","addr":"1295 Terminal Rd, RICHMOND, VA 87149","dot":"3315822","ph":"(627) 564-3170","sups":['ANTONIO BROWN', 'CHARLES MARTIN', 'PATRICIA ANDERSON']},
    {"name":"PREMIER FREIGHT SYSTEMS GROUP LLC","addr":"4385 Distribution Center Rd, KANSAS CITY, MO 23166","dot":"3011625","ph":"(479) 341-1797","sups":['ANTONIO WHITE', 'JOHN JONES', 'SUSAN HERNANDEZ']},
    {"name":"LIBERTY BELL COASTAL TRANSPORTATION INC","addr":"9972 Airport Rd, SHREVEPORT, LA 87546","dot":"2363098","ph":"(549) 644-6985","sups":['ELIZABETH CLARK', 'JESSICA RODRIGUEZ', 'DIANA SANCHEZ']},
    {"name":"TURNPIKE FREIGHT HOLDINGS INC","addr":"3736 Southpoint Dr, BATON ROUGE, LA 14884","dot":"884387","ph":"(872) 872-9488","sups":['ANA MOORE', 'MICHAEL THOMPSON', 'DAVID DAVIS']},
    {"name":"EXPRESS PINNACLE LOGISTICS LLC LP","addr":"3913 Park Ave, BIRMINGHAM, AL 13141","dot":"2539630","ph":"(556) 899-1671","sups":['SARAH MILLER', 'SARAH ROBINSON', 'THOMAS THOMPSON']},
    {"name":"VANGUARD GREEN VALLEY EXPRESS INC","addr":"640 Business Center Dr, SEATTLE, WA 44897","dot":"667906","ph":"(713) 647-4503","sups":['ANA MOORE', 'JENNIFER WHITE', 'MICHAEL GONZALEZ']},
    {"name":"NORTHERN STAR TRANSPORT SERVICES CORP","addr":"705 Eastgate Dr, MONTGOMERY, AL 61556","dot":"2460179","ph":"(507) 520-1472","sups":['JAMES ANDERSON', 'CARLOS CLARK', 'MARIA JONES']},
    {"name":"MOMENTUM EXPRESS CORP","addr":"7490 Freight Way, MOBILE, AL 78595","dot":"1444701","ph":"(965) 707-1405","sups":['CARLOS HERNANDEZ', 'ELIZABETH SMITH', 'PATRICIA RODRIGUEZ']},
    {"name":"EAGLE EAGLE CARRIERS INC CORP","addr":"328 Eastgate Dr, SHREVEPORT, LA 13630","dot":"2794229","ph":"(837) 643-6978","sups":['ANA GARCIA', 'JOSEPH RODRIGUEZ', 'ROBERT MILLER']},
    {"name":"EAGLE LOGISTICS GROUP INC","addr":"1761 Westside Dr, PORTLAND, OR 58665","dot":"3515586","ph":"(331) 569-2887","sups":['JESSICA RAMIREZ', 'MIGUEL SMITH', 'MARY BROWN']},
    {"name":"SWIFT LOGISTICS LLC HOLDINGS INC","addr":"8164 Terminal Rd, LUBBOCK, TX 61655","dot":"2579185","ph":"(764) 563-1664","sups":['PATRICIA THOMPSON', 'SUSAN SANCHEZ', 'THOMAS MILLER']},
    {"name":"MOMENTUM TRANSPORT LLC GROUP LLC","addr":"9831 Cargo Way, MINNEAPOLIS, MN 35451","dot":"3799455","ph":"(896) 382-4632","sups":['DAVID JONES', 'LUIS LOPEZ', 'ROBERT ROBINSON']},
    {"name":"TITAN TRANSPORTATION CO","addr":"9801 Enterprise Way, JOPLIN, MO 57254","dot":"3983140","ph":"(568) 659-6538","sups":['ROBERT TAYLOR', 'JOSEPH THOMAS', 'CHARLES DAVIS']},
    {"name":"MARTINEZ CARRIERS INC","addr":"5741 Northgate Blvd, HOUSTON, TX 16242","dot":"441922","ph":"(680) 853-9597","sups":['PATRICIA JONES', 'JAMES RODRIGUEZ', 'LUIS MARTIN']},
    {"name":"PLATINUM DIAMOND FREIGHTWAYS INC","addr":"780 Westside Dr, EL PASO, TX 95799","dot":"235236","ph":"(532) 838-8146","sups":['MICHAEL LEWIS', 'MICHAEL ROBINSON', 'MICHAEL JACKSON']},
    {"name":"LEE FREIGHT CORP","addr":"8958 Park Ave, AKRON, OH 59516","dot":"823233","ph":"(569) 293-6900","sups":['RICHARD JOHNSON', 'JOSE DAVIS', 'SOFIA WHITE']},
    {"name":"JONES HAULING CORP","addr":"1708 Trucking Ln, HOUSTON, TX 79400","dot":"2537010","ph":"(271) 912-7345","sups":['JOSE ANDERSON', 'ELIZABETH TAYLOR', 'ANTONIO JOHNSON']},
    {"name":"DESERT ROEHL TRUCKING HOLDINGS INC","addr":"7619 Fleet St, EL PASO, TX 39274","dot":"2463989","ph":"(729) 790-2174","sups":['RICHARD HARRIS', 'WILLIAM TAYLOR', 'JENNIFER DAVIS']},
    {"name":"TRANS DESERT LINES GROUP LLC","addr":"3628 Trucking Ln, DALLAS, TX 16279","dot":"2771309","ph":"(337) 397-8178","sups":['RICHARD SMITH', 'MARIA ROBINSON', 'RICHARD WILLIAMS']},
    {"name":"DIAMOND FREIGHT SYSTEMS ENTERPRISES LLC","addr":"8177 Airport Rd, SPOKANE, WA 84610","dot":"2426842","ph":"(240) 847-2774","sups":['SARAH PEREZ', 'MICHAEL ROBINSON', 'SARAH HARRIS']},
    {"name":"JB HUNT HIGHWAY TRUCKING CO","addr":"2351 Freight Way, OMAHA, NE 44925","dot":"2021873","ph":"(676) 336-3617","sups":['LAURA LEWIS', 'RICHARD THOMPSON', 'SARAH MARTIN']},
    {"name":"PACIFIC HAWK TRANSPORT LLC ENTERPRISES LLC","addr":"5261 Industrial Pkwy, MEMPHIS, TN 38197","dot":"310704","ph":"(249) 394-1546","sups":['ROBERT MARTIN', 'BARBARA ANDERSON', 'BARBARA ROBINSON']},
    {"name":"DIAMOND TRANSPORTATION LP","addr":"1233 Highway Dr, CORPUS CHRISTI, TX 23665","dot":"363871","ph":"(322) 436-7880","sups":['LAURA JONES', 'LAURA DAVIS', 'DAVID MILLER']},
    {"name":"PATRIOT GREEN VALLEY LINES HOLDINGS INC","addr":"5029 Corporate Dr, FORT WAYNE, IN 40458","dot":"2609203","ph":"(599) 972-8975","sups":['DAVID ROBINSON', 'ROBERT LOPEZ', 'ANA CLARK']},
    {"name":"SMITH FREIGHT SYSTEMS GROUP LLC","addr":"4468 Corporate Dr, SALT LAKE CITY, UT 26912","dot":"3482121","ph":"(351) 976-2538","sups":['THOMAS LEE', 'SOFIA WHITE', 'JOSEPH JACKSON']},
    {"name":"BLUE SKY TITAN FREIGHTWAYS ENTERPRISES LLC","addr":"8767 Park Ave, WICHITA, KS 13043","dot":"1403733","ph":"(510) 385-6952","sups":['DIANA HERNANDEZ', 'RICHARD DAVIS', 'MIGUEL WHITE']},
    {"name":"APEX PLAINS TRUCKING CO HOLDINGS INC","addr":"2343 Westside Dr, SPOKANE, WA 13778","dot":"892959","ph":"(507) 330-4510","sups":['JESSICA WILLIAMS', 'JENNIFER JOHNSON', 'ROBERT PEREZ']},
    {"name":"GARCIA TRANSPORT LLC LLC","addr":"4992 Industrial Way, BIRMINGHAM, AL 55650","dot":"1755931","ph":"(824) 542-6768","sups":['JESSICA RODRIGUEZ', 'JOHN SMITH', 'ANA THOMPSON']},
    {"name":"SILVER CARRIERS HOLDINGS INC","addr":"6576 Fleet St, TOLEDO, OH 14570","dot":"2094227","ph":"(836) 384-5977","sups":['MICHAEL WILLIAMS', 'LAURA HARRIS', 'LINDA JACKSON']},
    {"name":"LIBERTY LINES LLC","addr":"9535 Westside Dr, SHREVEPORT, LA 44140","dot":"3579782","ph":"(459) 848-1176","sups":['PATRICIA WILLIAMS', 'MIGUEL HARRIS', 'MIGUEL PEREZ']},
    {"name":"OLD DOMINION CARRIERS INC LP","addr":"9230 Trucking Ln, BAKERSFIELD, CA 87919","dot":"1038927","ph":"(851) 876-5977","sups":['JOHN ROBINSON', 'ANA WILSON', 'WILLIAM LOPEZ']},
    {"name":"USA HAWK FREIGHTWAYS LP","addr":"9954 Commerce Dr, ALBUQUERQUE, NM 66520","dot":"1254388","ph":"(497) 470-6449","sups":['MIGUEL LOPEZ', 'THOMAS WILLIAMS', 'CARLOS LOPEZ']},
    {"name":"SCHNEIDER EXPRESS HOLDINGS INC","addr":"4157 Enterprise Way, CHARLOTTE, NC 38556","dot":"3084114","ph":"(313) 256-8423","sups":['SOFIA LEE', 'RICHARD DAVIS', 'KAREN BROWN']},
    {"name":"COVENANT TRANSPORT SERVICES CORP","addr":"3928 Trucking Ln, SEATTLE, WA 34880","dot":"2879888","ph":"(799) 622-4292","sups":['LUIS MILLER', 'JOSEPH CLARK', 'JENNIFER MARTIN']},
    {"name":"NEXUS TITAN LOGISTICS LP","addr":"1068 Business Center Dr, TOLEDO, OH 21211","dot":"2475740","ph":"(496) 666-5694","sups":['MIGUEL RODRIGUEZ', 'JAMES JACKSON', 'LINDA DAVIS']},
    {"name":"ANDERSON EXPRESS CORP","addr":"236 Corporate Dr, JOPLIN, MO 51177","dot":"2921324","ph":"(675) 220-1600","sups":['JOSEPH LOPEZ', 'ANA HARRIS', 'MARIA HERNANDEZ']},
    {"name":"GOLD SOUTHERN TRANSPORT SERVICES ENTERPRISES LLC","addr":"9905 Fleet St, DALLAS, TX 34782","dot":"3493451","ph":"(466) 961-1146","sups":['JOSEPH SANCHEZ', 'CARLOS RODRIGUEZ', 'SUSAN BROWN']},
    {"name":"MOMENTUM LOGISTICS LLC CO","addr":"4730 Fleet St, LITTLE ROCK, AR 15230","dot":"198690","ph":"(437) 982-4714","sups":['RICHARD GONZALEZ', 'ELIZABETH PEREZ', 'THOMAS WHITE']},
    {"name":"EASTERN TRANSPORT SERVICES GROUP LLC","addr":"4700 Enterprise Way, MEMPHIS, TN 63276","dot":"739418","ph":"(778) 229-3869","sups":['KAREN LEWIS', 'JESSICA PEREZ', 'WILLIAM JOHNSON']},
    {"name":"HORIZON LAKESIDE LINES LLC","addr":"1732 Trucking Ln, LUBBOCK, TX 43246","dot":"3955753","ph":"(263) 930-4362","sups":['CHARLES THOMPSON', 'SARAH JOHNSON', 'WILLIAM WILSON']},
    {"name":"USA FREIGHT LP","addr":"7228 Distribution Center Rd, AKRON, OH 29026","dot":"1734004","ph":"(501) 975-2657","sups":['JESSICA GONZALEZ', 'WILLIAM JACKSON', 'CHARLES PEREZ']},
    {"name":"EXPRESS RUSH LOGISTICS GROUP LLC","addr":"6021 Depot St, LAREDO, TX 66876","dot":"1800735","ph":"(973) 951-8609","sups":['JESSICA GONZALEZ', 'MIGUEL MARTIN', 'KAREN LOPEZ']},
    {"name":"MILLER LOGISTICS LLC LLC","addr":"8074 Freight Way, COLUMBUS, OH 13576","dot":"2892086","ph":"(466) 641-8505","sups":['ROBERT RODRIGUEZ', 'DIANA HARRIS', 'THOMAS MARTINEZ']},
    {"name":"SOUTHERN DIAMOND LOGISTICS GROUP HOLDINGS INC","addr":"5689 Terminal Rd, FRESNO, CA 14412","dot":"1693007","ph":"(831) 270-3210","sups":['PATRICIA MARTINEZ', 'MARIA MOORE', 'LAURA PEREZ']},
    {"name":"SCHNEIDER MOMENTUM TRANSPORTATION LP","addr":"5904 Business Center Dr, SEATTLE, WA 88607","dot":"623598","ph":"(702) 434-8637","sups":['MARY SMITH', 'ELIZABETH BROWN', 'SARAH MARTIN']},
    {"name":"APEX TRUCKING INC","addr":"3103 Eastgate Dr, JOPLIN, MO 94845","dot":"3421951","ph":"(341) 571-3173","sups":['ELIZABETH CLARK', 'THOMAS SMITH', 'JOSE MILLER']},
    {"name":"PLAINS TRUCKING CO","addr":"8150 Commerce Dr, DES MOINES, IA 85867","dot":"3248016","ph":"(306) 560-3214","sups":['CARLOS GONZALEZ', 'THOMAS MOORE', 'SUSAN JACKSON']},
    {"name":"APEX LINES CO","addr":"1377 Freight Way, SEATTLE, WA 99373","dot":"458483","ph":"(974) 365-3963","sups":['BARBARA MARTIN', 'MARY LEWIS', 'LAURA WHITE']},
    {"name":"GREEN VALLEY TRANSPORT INC","addr":"5093 Eastgate Dr, LOUISVILLE, KY 31686","dot":"2466438","ph":"(982) 775-6433","sups":['JOSEPH ANDERSON', 'PATRICIA THOMAS', 'JESSICA ANDERSON']},
    {"name":"HERITAGE LOGISTICS LLC CORP","addr":"7201 Logistics Blvd, SHREVEPORT, LA 57664","dot":"3925667","ph":"(255) 643-9452","sups":['LUIS MARTINEZ', 'ANA TAYLOR', 'SOFIA DAVIS']},
    {"name":"GREEN VALLEY FREIGHTWAYS ENTERPRISES LLC","addr":"5369 Business Center Dr, COLUMBIA, SC 74668","dot":"3193057","ph":"(956) 504-8383","sups":['LUIS WILLIAMS', 'BARBARA JOHNSON', 'BARBARA WILLIAMS']},
    {"name":"HAWK LEGACY TRUCKING CO LP","addr":"1209 Corporate Dr, INDIANAPOLIS, IN 85909","dot":"2910406","ph":"(273) 397-9924","sups":['THOMAS TAYLOR', 'BARBARA RAMIREZ', 'JOSEPH THOMAS']},
    {"name":"MOMENTUM HEARTLAND LOGISTICS ENTERPRISES LLC","addr":"150 Highway Dr, CHARLOTTE, NC 52593","dot":"3264451","ph":"(929) 851-5803","sups":['JAMES MILLER', 'ANA JACKSON', 'JENNIFER BROWN']},
    {"name":"ALL AMERICAN CARRIERS INC CO","addr":"9298 Business Center Dr, ATLANTA, GA 91194","dot":"759887","ph":"(670) 692-3999","sups":['PATRICIA THOMAS', 'DAVID JOHNSON', 'JESSICA SANCHEZ']},
    {"name":"FRONTIER LINES CORP","addr":"6219 Eastgate Dr, JOPLIN, MO 97027","dot":"2458874","ph":"(907) 401-6960","sups":['JAMES HERNANDEZ', 'LAURA THOMPSON', 'MARIA MARTIN']},
    {"name":"RED RIVER TRANSPORT CORP","addr":"1124 Westside Dr, CHARLOTTE, NC 97958","dot":"1365011","ph":"(584) 934-7049","sups":['LUIS WHITE', 'KAREN MILLER', 'ELIZABETH HERNANDEZ']},
    {"name":"APEX CARRIERS CO","addr":"6771 Fleet St, EVANSVILLE, IN 61384","dot":"3253329","ph":"(724) 444-5250","sups":['JESSICA LEWIS', 'LAURA WHITE', 'JESSICA MARTIN']},
    {"name":"FREIGHT LOGISTICS GROUP HOLDINGS INC","addr":"7616 Commerce Dr, MILWAUKEE, WI 33940","dot":"3577577","ph":"(804) 690-7025","sups":['CARLOS WILSON', 'WILLIAM ROBINSON', 'ELIZABETH GONZALEZ']},
    {"name":"VANGUARD EXPRESS FREIGHT GROUP LLC","addr":"4401 Fleet St, AMARILLO, TX 68466","dot":"2937587","ph":"(950) 597-1581","sups":['KAREN WILLIAMS', 'MARY SMITH', 'PATRICIA DAVIS']},
    {"name":"NATIONAL FREIGHTWAYS HOLDINGS INC","addr":"1196 Commerce Dr, FORT WORTH, TX 68995","dot":"1246621","ph":"(321) 373-6217","sups":['KAREN DAVIS', 'JENNIFER CLARK', 'JOSE WHITE']},
    {"name":"KNIGHT VELOCITY TRANSPORT SERVICES ENTERPRISES LLC","addr":"5314 Airport Rd, INDIANAPOLIS, IN 39401","dot":"3645221","ph":"(986) 523-9481","sups":['THOMAS RAMIREZ', 'LUIS CLARK', 'JOSEPH MILLER']},
    {"name":"EXPRESS LIBERTY FREIGHT LP","addr":"8057 Fleet St, KNOXVILLE, TN 82677","dot":"793675","ph":"(359) 361-2856","sups":['LUIS HERNANDEZ', 'SARAH LOPEZ', 'ROBERT GARCIA']},
    {"name":"WILLIAMS TRANSPORTATION GROUP LLC","addr":"9473 Broad St, OMAHA, NE 39315","dot":"3726091","ph":"(910) 234-8653","sups":['THOMAS JACKSON', 'LUIS RODRIGUEZ', 'LAURA PEREZ']},
    {"name":"LIBERTY BELL PLAINS FREIGHT SYSTEMS HOLDINGS INC","addr":"5740 Broad St, MOBILE, AL 90180","dot":"1608307","ph":"(984) 687-9376","sups":['DAVID RAMIREZ', 'CHARLES JACKSON', 'PATRICIA JOHNSON']},
    {"name":"FOUNDERS TRANSPORT CORP","addr":"5219 Westside Dr, BOISE, ID 85945","dot":"2133057","ph":"(562) 576-9095","sups":['RICHARD THOMAS', 'DIANA ANDERSON', 'LUIS LEE']},
    {"name":"COVENANT NORTHERN HAULING GROUP LLC","addr":"9461 Industrial Pkwy, TOLEDO, OH 99154","dot":"3262771","ph":"(753) 974-3073","sups":['SARAH LEE', 'JOSE WILSON', 'SUSAN ROBINSON']},
    {"name":"MARTEN TRUCKING CORP","addr":"3334 Freight Way, HOUSTON, TX 81932","dot":"306010","ph":"(754) 594-2304","sups":['JOSE LEE', 'CARLOS TAYLOR', 'ELIZABETH LEE']},
    {"name":"ATLANTIC LOGISTICS INC","addr":"708 Westside Dr, AMARILLO, TX 77267","dot":"1579168","ph":"(504) 466-7218","sups":['ELIZABETH JONES', 'LUIS HARRIS', 'PATRICIA ROBINSON']},
    {"name":"MOMENTUM PLATINUM FREIGHT GROUP LLC","addr":"9215 Cargo Way, DAYTON, OH 43935","dot":"2670111","ph":"(414) 602-9910","sups":['ROBERT MILLER', 'JOSEPH LOPEZ', 'ELIZABETH RODRIGUEZ']},
    {"name":"RED RIVER INDEPENDENCE TRANSPORT LLC LP","addr":"9740 Fleet St, GREENSBORO, NC 94944","dot":"583454","ph":"(220) 223-9357","sups":['WILLIAM WILLIAMS', 'SUSAN MILLER', 'LUIS PEREZ']},
    {"name":"HERNANDEZ TRANSPORTATION CO","addr":"2552 Business Center Dr, TULSA, OK 32575","dot":"3817695","ph":"(915) 760-2398","sups":['ROBERT CLARK', 'RICHARD SANCHEZ', 'ANTONIO GARCIA']},
    {"name":"PATRIOT TRANSPORT LLC INC","addr":"3670 Distribution Center Rd, MCALLEN, TX 72957","dot":"2033083","ph":"(745) 345-8190","sups":['ELIZABETH ANDERSON', 'CHARLES JONES', 'JENNIFER WILLIAMS']},
    {"name":"SILVER LOGISTICS GROUP CORP","addr":"7041 Freight Way, WICHITA, KS 48879","dot":"2951835","ph":"(978) 720-5192","sups":['JAMES THOMPSON', 'BARBARA JOHNSON', 'KAREN ANDERSON']},
    {"name":"WHITE CARRIERS CORP","addr":"3078 Depot St, TULSA, OK 66097","dot":"3185962","ph":"(558) 932-7211","sups":['JAMES CLARK', 'JENNIFER GARCIA', 'JESSICA GARCIA']},
    {"name":"MIDWEST LOGISTICS LLC INC","addr":"5618 Park Ave, LUBBOCK, TX 61029","dot":"3642011","ph":"(238) 580-7689","sups":['MICHAEL MILLER', 'JOHN PEREZ', 'ANA MARTIN']},
    {"name":"GREEN VALLEY ALL AMERICAN CARRIERS GROUP LLC","addr":"3944 Westside Dr, ATLANTA, GA 58667","dot":"3548764","ph":"(556) 435-8706","sups":['JOSEPH LOPEZ', 'SARAH THOMAS', 'LAURA LEWIS']},
    {"name":"ROYAL BLUE SKY TRANSPORTATION LP","addr":"3161 Depot St, BAKERSFIELD, CA 36980","dot":"1323759","ph":"(492) 500-9353","sups":['SUSAN WILLIAMS', 'JAMES LOPEZ', 'SOFIA TAYLOR']},
    {"name":"IRON FREIGHTWAYS CORP","addr":"7610 Terminal Rd, SAN ANTONIO, TX 62013","dot":"1122126","ph":"(919) 796-8984","sups":['LAURA ANDERSON', 'MICHAEL WILSON', 'ELIZABETH LEWIS']},
    {"name":"PATRIOT TRANSPORT LLC HOLDINGS INC","addr":"8536 Trucking Ln, NASHVILLE, TN 34035","dot":"1541917","ph":"(573) 854-3178","sups":['JAMES MILLER', 'DAVID MILLER', 'JENNIFER PEREZ']},
    {"name":"FREIGHT USA CARRIERS LP","addr":"1372 Terminal Rd, OKLAHOMA CITY, OK 51787","dot":"3724130","ph":"(828) 601-7100","sups":['RICHARD LOPEZ', 'JOSE LOPEZ', 'MARY JOHNSON']},
    {"name":"MARTEN TRUCKING ENTERPRISES LLC","addr":"2435 Southpoint Dr, COLUMBUS, OH 98910","dot":"3834356","ph":"(673) 854-5640","sups":['SUSAN LEE', 'ELIZABETH JONES', 'JOSE SMITH']},
    {"name":"WILLIAMS CARRIERS INC ENTERPRISES LLC","addr":"7254 Industrial Way, DAYTON, OH 20065","dot":"845132","ph":"(748) 355-4641","sups":['JOSE MOORE', 'JESSICA DAVIS', 'PATRICIA DAVIS']},
    {"name":"BIG RIG EXPRESS INC","addr":"7363 Northgate Blvd, BATON ROUGE, LA 84893","dot":"1168185","ph":"(259) 981-6706","sups":['ROBERT BROWN', 'MARY HERNANDEZ', 'JOSEPH ANDERSON']},
    {"name":"WERNER TRUCKING CORP","addr":"3644 Fleet St, DAYTON, OH 60694","dot":"567726","ph":"(934) 810-9672","sups":['CARLOS LEE', 'ELIZABETH MARTINEZ', 'ELIZABETH PEREZ']},
    {"name":"HARRIS LINES LP","addr":"7372 Logistics Blvd, JOPLIN, MO 72080","dot":"1663444","ph":"(487) 498-5350","sups":['ELIZABETH DAVIS', 'PATRICIA SMITH', 'ROBERT JOHNSON']},
    {"name":"WESTERN LINES HOLDINGS INC","addr":"1259 Westside Dr, AKRON, OH 70432","dot":"1260033","ph":"(267) 739-9094","sups":['ELIZABETH TAYLOR', 'DAVID MARTIN', 'CARLOS WHITE']},
    {"name":"SOUTHERN FREIGHT SYSTEMS INC","addr":"1769 Fleet St, SPRINGFIELD, MO 11179","dot":"2416322","ph":"(667) 474-1624","sups":['SUSAN MOORE', 'SUSAN PEREZ', 'RICHARD PEREZ']},
    {"name":"CROSS COUNTRY EAGLE HAULING HOLDINGS INC","addr":"8776 Highway Dr, TULSA, OK 32800","dot":"3318203","ph":"(392) 401-1508","sups":['MICHAEL JOHNSON', 'DIANA WHITE', 'PATRICIA THOMAS']},
    {"name":"ANDERSON CARRIERS INC CO","addr":"2984 Trucking Ln, CHATTANOOGA, TN 35402","dot":"3662921","ph":"(980) 448-7868","sups":['LINDA WILSON', 'MARY ROBINSON', 'BARBARA LEWIS']},
    {"name":"VANGUARD FREIGHT LLC","addr":"6841 Depot St, MEMPHIS, TN 80106","dot":"1002637","ph":"(467) 723-8623","sups":['JOHN LEE', 'SUSAN MARTINEZ', 'CARLOS GONZALEZ']},
    {"name":"APEX CARRIERS INC GROUP LLC","addr":"9752 Main St, NASHVILLE, TN 95269","dot":"2952484","ph":"(835) 341-1371","sups":['RICHARD PEREZ', 'CHARLES MOORE', 'JOSE BROWN']},
    {"name":"RAMIREZ EXPRESS CO","addr":"7177 Main St, SAN ANTONIO, TX 27647","dot":"3860774","ph":"(795) 308-2496","sups":['SARAH TAYLOR', 'MARY PEREZ', 'SUSAN TAYLOR']},
    {"name":"DESERT SHIPPING INC","addr":"7515 Broad St, DALLAS, TX 88028","dot":"1653437","ph":"(279) 396-9181","sups":['SUSAN ROBINSON', 'PATRICIA THOMAS', 'CHARLES LEWIS']},
    {"name":"CLARK EXPRESS INC","addr":"1106 Park Ave, TULSA, OK 74857","dot":"1776860","ph":"(879) 515-6536","sups":['SARAH GARCIA', 'JAMES MARTIN', 'MICHAEL LEE']},
    {"name":"GONZALEZ FREIGHT SYSTEMS GROUP LLC","addr":"7160 Enterprise Way, LAREDO, TX 44689","dot":"1273368","ph":"(751) 888-3967","sups":['KAREN WILSON', 'LAURA HARRIS', 'SOFIA CLARK']},
    {"name":"MIDWEST FREIGHTWAYS INC","addr":"4179 Enterprise Way, RICHMOND, VA 48925","dot":"1452967","ph":"(673) 791-2379","sups":['RICHARD PEREZ', 'JAMES GARCIA', 'JAMES HARRIS']},
    {"name":"COVENANT CARRIERS INC LLC","addr":"1635 Industrial Pkwy, CHARLOTTE, NC 63680","dot":"1330815","ph":"(432) 719-7837","sups":['BARBARA DAVIS', 'JESSICA ANDERSON', 'JOHN LEWIS']},
    {"name":"ALL AMERICAN CARRIERS GROUP LLC","addr":"2195 Main St, LOUISVILLE, KY 56641","dot":"3940065","ph":"(329) 901-7116","sups":['JENNIFER DAVIS', 'SARAH TAYLOR', 'ANA JOHNSON']},
    {"name":"GOLD LOGISTICS ENTERPRISES LLC","addr":"7465 Westside Dr, MOBILE, AL 22880","dot":"2981942","ph":"(594) 882-1997","sups":['LAURA LEWIS', 'JOSE THOMPSON', 'LINDA CLARK']},
    {"name":"TURNPIKE NORTHERN FREIGHTWAYS ENTERPRISES LLC","addr":"1133 Distribution Center Rd, CHATTANOOGA, TN 41886","dot":"1973198","ph":"(759) 861-3654","sups":['DAVID DAVIS', 'ELIZABETH LEE', 'ANA WILLIAMS']},
    {"name":"LEGACY TRUCKING HOLDINGS INC","addr":"2165 Northgate Blvd, LANSING, MI 57509","dot":"328609","ph":"(439) 942-5284","sups":['MARIA JOHNSON', 'SOFIA SMITH', 'ANTONIO SMITH']},
    {"name":"SILVER FREEDOM HAULING LP","addr":"6131 Business Center Dr, SAN ANTONIO, TX 81191","dot":"742821","ph":"(443) 268-7164","sups":['ROBERT MARTINEZ', 'JAMES MARTIN', 'CHARLES DAVIS']},
    {"name":"INDEPENDENCE LOAD STAR TRANSPORT LLC CORP","addr":"4569 Terminal Rd, MILWAUKEE, WI 35517","dot":"1416781","ph":"(572) 359-2148","sups":['LINDA DAVIS', 'LUIS RODRIGUEZ', 'BARBARA HARRIS']},
    {"name":"GOLD TRUCKING CO CO","addr":"4244 Industrial Way, SAN ANTONIO, TX 88644","dot":"2027428","ph":"(380) 330-3342","sups":['PATRICIA PEREZ', 'MIGUEL HARRIS', 'LAURA LEWIS']},
    {"name":"TRANS LINES INC","addr":"5066 Industrial Pkwy, CHICAGO, IL 17967","dot":"2418511","ph":"(370) 259-7878","sups":['SOFIA MARTIN', 'BARBARA LOPEZ', 'ROBERT TAYLOR']},
    {"name":"MOUNTAIN TRANSPORT SERVICES LLC","addr":"7813 Eastgate Dr, INDIANAPOLIS, IN 88387","dot":"2450677","ph":"(423) 899-6666","sups":['MARIA WHITE', 'MIGUEL MARTINEZ', 'ANTONIO CLARK']},
    {"name":"COASTAL LOGISTICS HOLDINGS INC","addr":"6371 Northgate Blvd, HOUSTON, TX 54661","dot":"776717","ph":"(950) 439-8190","sups":['ROBERT MARTIN', 'WILLIAM HERNANDEZ', 'LINDA WILSON']},
    {"name":"HORIZON TRANSPORTATION LLC","addr":"4909 Airport Rd, AUSTIN, TX 57429","dot":"3187503","ph":"(271) 793-4768","sups":['ELIZABETH THOMPSON', 'MIGUEL JOHNSON', 'DAVID LEWIS']},
    {"name":"SYNERGY EXPRESS LLC","addr":"6135 Broad St, MILWAUKEE, WI 21004","dot":"457940","ph":"(268) 876-6747","sups":['JOSEPH SMITH', 'CARLOS LEE', 'SUSAN RAMIREZ']},
    {"name":"DESERT LOGISTICS LLC","addr":"8058 Park Ave, MILWAUKEE, WI 87731","dot":"1900550","ph":"(415) 318-1198","sups":['JOSEPH LEWIS', 'CHARLES JONES', 'LUIS MARTINEZ']},
    {"name":"ROAD KING KNIGHT HAULING HOLDINGS INC","addr":"3769 Industrial Pkwy, CHICAGO, IL 20008","dot":"948902","ph":"(529) 415-7343","sups":['LAURA SMITH', 'JESSICA SANCHEZ', 'SUSAN DAVIS']},
    {"name":"MOUNTAIN LINES INC","addr":"4302 Freight Way, SPRINGFIELD, MO 82971","dot":"1310363","ph":"(666) 862-8456","sups":['DIANA BROWN', 'THOMAS SANCHEZ', 'LAURA MARTINEZ']},
    {"name":"COAST TO COAST WESTERN TRANSPORT CO","addr":"5183 Westside Dr, FRESNO, CA 18630","dot":"2924127","ph":"(370) 593-2301","sups":['ELIZABETH MARTINEZ', 'JESSICA DAVIS', 'SOFIA RODRIGUEZ']},
    {"name":"NATIONAL TRANSPORTATION GROUP LLC","addr":"7301 Industrial Pkwy, BOISE, ID 22449","dot":"158962","ph":"(563) 865-5869","sups":['JESSICA MILLER', 'JENNIFER ROBINSON', 'LINDA TAYLOR']},
    {"name":"PACIFIC FREIGHT CORP","addr":"6230 Eastgate Dr, OMAHA, NE 17138","dot":"1146197","ph":"(980) 986-4692","sups":['LINDA LEWIS', 'THOMAS GONZALEZ', 'SARAH SMITH']},
    {"name":"BIG RIG SHIPPING HOLDINGS INC","addr":"3360 Corporate Dr, PHOENIX, AZ 44167","dot":"2045377","ph":"(530) 767-9399","sups":['JOSE LEE', 'ANA WHITE', 'MIGUEL LOPEZ']},
    {"name":"TRAIL BLAZER TRANSPORTATION LLC","addr":"2811 Corporate Dr, OMAHA, NE 37160","dot":"2930292","ph":"(350) 880-1540","sups":['MIGUEL WILSON', 'JOSE GARCIA', 'ROBERT LEE']},
    {"name":"THOMAS FREIGHT LLC","addr":"4641 Industrial Pkwy, MINNEAPOLIS, MN 23376","dot":"1262125","ph":"(252) 946-4336","sups":['RICHARD LEE', 'WILLIAM PEREZ', 'CHARLES TAYLOR']},
    {"name":"USA PINNACLE LOGISTICS LLC INC","addr":"3434 Terminal Rd, INDIANAPOLIS, IN 17061","dot":"1520056","ph":"(793) 939-6497","sups":['ANTONIO THOMPSON', 'ANTONIO RAMIREZ', 'JOHN THOMAS']},
    {"name":"TRANS MOUNTAIN LOGISTICS LLC GROUP LLC","addr":"9952 Trucking Ln, HOUSTON, TX 26220","dot":"2757002","ph":"(241) 312-9399","sups":['BARBARA JOHNSON', 'MARY RAMIREZ', 'LUIS HARRIS']},
    {"name":"HERITAGE SHIPPING CORP","addr":"452 Corporate Dr, RENO, NV 10811","dot":"1938605","ph":"(280) 994-4813","sups":['LAURA MARTINEZ', 'JOSEPH JOHNSON', 'WILLIAM WILSON']},
    {"name":"FREEDOM NORTHERN LINES LP","addr":"8078 Terminal Rd, LITTLE ROCK, AR 59562","dot":"3260382","ph":"(841) 353-1705","sups":['JENNIFER WHITE', 'JAMES BROWN', 'KAREN LEE']},
    {"name":"FRONTIER EAGLE TRUCKING ENTERPRISES LLC","addr":"7984 Westside Dr, ATLANTA, GA 88504","dot":"919467","ph":"(847) 402-3439","sups":['DAVID CLARK', 'MICHAEL MARTIN', 'JESSICA THOMPSON']},
    {"name":"STERLING TRANSPORTATION GROUP LLC","addr":"7841 Southpoint Dr, OMAHA, NE 58026","dot":"3979126","ph":"(653) 672-1435","sups":['CARLOS LEE', 'MARY TAYLOR', 'WILLIAM SANCHEZ']},
    {"name":"JONES FREIGHT SYSTEMS ENTERPRISES LLC","addr":"3123 Airport Rd, MONTGOMERY, AL 13817","dot":"3417710","ph":"(814) 851-5265","sups":['JOSE WILLIAMS', 'MIGUEL DAVIS', 'DAVID BROWN']},
    {"name":"CROWN CARRIERS INC CORP","addr":"4827 Business Center Dr, LUBBOCK, TX 47192","dot":"2229151","ph":"(822) 972-4248","sups":['JAMES JACKSON', 'ANTONIO ROBINSON', 'ANA MOORE']},
    {"name":"FREIGHT FREIGHT CO","addr":"8317 Cargo Way, WICHITA, KS 93918","dot":"2620674","ph":"(333) 652-5083","sups":['LUIS MARTIN', 'ROBERT JACKSON', 'MARIA MARTIN']},
    {"name":"STERLING LINES CO","addr":"6816 Airport Rd, BATON ROUGE, LA 63572","dot":"955651","ph":"(551) 990-9452","sups":['CARLOS JONES', 'ANA MOORE', 'CHARLES RODRIGUEZ']},
    {"name":"XPO ALL AMERICAN LOGISTICS LLC CO","addr":"5984 Depot St, PORTLAND, OR 53120","dot":"1386896","ph":"(335) 844-4059","sups":['ANTONIO TAYLOR', 'JENNIFER MILLER', 'LINDA MOORE']},
    {"name":"FREEDOM ESTES HAULING ENTERPRISES LLC","addr":"6960 Corporate Dr, GREENSBORO, NC 53470","dot":"136643","ph":"(884) 940-1875","sups":['JAMES JONES', 'SOFIA ROBINSON', 'JOSE THOMPSON']},
    {"name":"WESTERN CARRIERS INC CO","addr":"9610 Enterprise Way, MEMPHIS, TN 38546","dot":"3499722","ph":"(322) 238-3092","sups":['ROBERT CLARK', 'BARBARA TAYLOR', 'CHARLES HARRIS']},
    {"name":"TITAN TRANSPORT SERVICES ENTERPRISES LLC","addr":"7239 Depot St, AMARILLO, TX 34831","dot":"225977","ph":"(597) 625-1213","sups":['JESSICA ROBINSON', 'MIGUEL RAMIREZ', 'RICHARD ROBINSON']},
    {"name":"ALL AMERICAN ROEHL TRANSPORT LLC LP","addr":"6588 Commerce Dr, HOUSTON, TX 36457","dot":"3679625","ph":"(291) 625-3203","sups":['ROBERT LOPEZ', 'JESSICA TAYLOR', 'WILLIAM RAMIREZ']},
    {"name":"MARTINEZ LOGISTICS INC","addr":"6177 Logistics Blvd, GREENSBORO, NC 19994","dot":"1857237","ph":"(956) 558-1647","sups":['LINDA WHITE', 'SUSAN RAMIREZ', 'THOMAS TAYLOR']},
    {"name":"NORTHERN LOGISTICS LP","addr":"3114 Terminal Rd, LAS VEGAS, NV 63367","dot":"3164269","ph":"(236) 830-7931","sups":['ANTONIO JONES', 'ANTONIO WILSON', 'SUSAN BROWN']},
    {"name":"RED RIVER LOGISTICS LLC CORP","addr":"8674 Fleet St, AKRON, OH 65397","dot":"3703777","ph":"(471) 406-1433","sups":['SUSAN WILLIAMS', 'ANTONIO MARTIN', 'MIGUEL PEREZ']},
    {"name":"KNIGHT PREMIER TRUCKING CO GROUP LLC","addr":"9182 Broad St, FORT WAYNE, IN 69469","dot":"343121","ph":"(281) 388-5927","sups":['KAREN LEWIS', 'LUIS SANCHEZ', 'LUIS SMITH']},
    {"name":"BROWN FREIGHT SYSTEMS CO","addr":"3964 Corporate Dr, SPRINGFIELD, MO 88191","dot":"3034715","ph":"(966) 812-8029","sups":['JOSEPH MILLER', 'LAURA MARTINEZ', 'SUSAN WILLIAMS']},
    {"name":"APEX TRANSPORT LLC GROUP LLC","addr":"8158 Main St, BATON ROUGE, LA 22216","dot":"2133590","ph":"(929) 628-5270","sups":['ANA RODRIGUEZ', 'WILLIAM JONES', 'JOSE DAVIS']},
    {"name":"INTERSTATE EXPRESS LP","addr":"8430 Logistics Blvd, PORTLAND, OR 57706","dot":"1476650","ph":"(944) 417-4490","sups":['SARAH HERNANDEZ', 'MIGUEL THOMAS', 'MICHAEL LEE']},
    {"name":"SOUTHERN TRANSPORTATION CORP","addr":"9602 Enterprise Way, LUBBOCK, TX 76467","dot":"782611","ph":"(230) 531-9948","sups":['MIGUEL RODRIGUEZ', 'LUIS LEE', 'JOSEPH PEREZ']},
    {"name":"JB HUNT STERLING TRUCKING CO LP","addr":"6008 Northgate Blvd, OMAHA, NE 86921","dot":"2428051","ph":"(725) 901-3448","sups":['JOHN JACKSON', 'ANA JONES', 'MARIA WILLIAMS']},
    {"name":"FREEDOM TRANSPORT CO","addr":"7675 Trucking Ln, SPRINGFIELD, MO 92797","dot":"1260971","ph":"(448) 659-2957","sups":['ROBERT MARTIN', 'CARLOS RAMIREZ', 'DIANA SANCHEZ']},
    {"name":"NORTHERN UNITED TRANSPORT SERVICES HOLDINGS INC","addr":"6048 Eastgate Dr, GREENSBORO, NC 64384","dot":"3244480","ph":"(402) 959-2738","sups":['MICHAEL MILLER', 'MARIA RODRIGUEZ', 'RICHARD SANCHEZ']},
    {"name":"MOUNTAIN EXPRESS INC","addr":"1121 Airport Rd, LOUISVILLE, KY 64039","dot":"2945393","ph":"(321) 992-1102","sups":['SARAH JONES', 'SOFIA WHITE', 'ROBERT LOPEZ']},
    {"name":"PEREZ TRANSPORT LLC ENTERPRISES LLC","addr":"2525 Business Center Dr, WICHITA, KS 25945","dot":"2164694","ph":"(538) 203-4428","sups":['LINDA MOORE', 'ANA TAYLOR', 'JOSEPH RODRIGUEZ']},
    {"name":"CARGO MASTER COASTAL TRANSPORT SERVICES GROUP LLC","addr":"5201 Fleet St, FORT WORTH, TX 22523","dot":"1627325","ph":"(686) 386-1861","sups":['SARAH LEE', 'DAVID RODRIGUEZ', 'MICHAEL MOORE']},
    {"name":"HIGHWAY PINNACLE LINES HOLDINGS INC","addr":"4564 Trucking Ln, TOLEDO, OH 79461","dot":"1274539","ph":"(916) 581-2140","sups":['THOMAS WILSON', 'ANTONIO JACKSON', 'JOSEPH JACKSON']},
    {"name":"SMITH TRANSPORT SERVICES GROUP LLC","addr":"9641 Corporate Dr, AMARILLO, TX 48273","dot":"3991931","ph":"(481) 306-8777","sups":['ROBERT DAVIS', 'ROBERT HERNANDEZ', 'JENNIFER THOMPSON']},
    {"name":"THOMAS CARRIERS INC LLC","addr":"2486 Broad St, CHATTANOOGA, TN 72785","dot":"707629","ph":"(834) 985-7000","sups":['SOFIA GARCIA', 'MICHAEL HARRIS', 'JAMES RODRIGUEZ']},
    {"name":"WILLIAMS SHIPPING HOLDINGS INC","addr":"6513 Airport Rd, CHARLOTTE, NC 31281","dot":"2815903","ph":"(609) 830-1405","sups":['CHARLES MOORE', 'RICHARD HERNANDEZ', 'SUSAN JOHNSON']},
    {"name":"LAKESIDE CARRIERS INC GROUP LLC","addr":"187 Trucking Ln, HOUSTON, TX 84336","dot":"2384519","ph":"(673) 834-4546","sups":['JAMES ROBINSON', 'CARLOS RODRIGUEZ', 'JESSICA MILLER']},
    {"name":"VELOCITY TRANSPORT LLC CORP","addr":"6344 Broad St, CHATTANOOGA, TN 52740","dot":"898966","ph":"(530) 862-8015","sups":['JOHN BROWN', 'ROBERT WILLIAMS', 'MIGUEL CLARK']},
    {"name":"SWIFT CARRIERS ENTERPRISES LLC","addr":"5084 Trucking Ln, GREENSBORO, NC 98991","dot":"2342554","ph":"(556) 785-3629","sups":['WILLIAM WILSON', 'ELIZABETH DAVIS', 'JOSE DAVIS']},
    {"name":"EASTERN VELOCITY HAULING INC","addr":"8766 Airport Rd, CHATTANOOGA, TN 86270","dot":"3750791","ph":"(262) 708-3578","sups":['ANTONIO ANDERSON', 'BARBARA BROWN', 'MARY LOPEZ']},
    {"name":"SOUTHERN LOGISTICS LLC GROUP LLC","addr":"2808 Trucking Ln, OKLAHOMA CITY, OK 83418","dot":"1386641","ph":"(545) 267-1380","sups":['ANA GARCIA', 'JOSE LEE', 'JOHN CLARK']},
    {"name":"TRAIL BLAZER STERLING FREIGHT HOLDINGS INC","addr":"7391 Distribution Center Rd, AUSTIN, TX 57865","dot":"1026487","ph":"(626) 416-2795","sups":['MIGUEL GARCIA', 'ELIZABETH DAVIS', 'KAREN MARTINEZ']},
    {"name":"USA EXPRESS CO","addr":"5751 Business Center Dr, DES MOINES, IA 97140","dot":"1017141","ph":"(436) 452-6056","sups":['CHARLES MARTINEZ', 'SUSAN LOPEZ', 'CHARLES GONZALEZ']},
    {"name":"PATRIOT LIBERTY FREIGHT CO","addr":"6576 Corporate Dr, JACKSON, MS 23376","dot":"1480924","ph":"(449) 281-3485","sups":['PATRICIA JOHNSON', 'PATRICIA GONZALEZ', 'THOMAS WILLIAMS']},
    {"name":"JOHNSON EXPRESS LP","addr":"9283 Fleet St, SPOKANE, WA 52951","dot":"2517873","ph":"(610) 445-2333","sups":['LINDA MARTINEZ', 'JESSICA ANDERSON', 'JOHN GARCIA']},
    {"name":"LIBERTY BELL TRANSPORT LP","addr":"8294 Cargo Way, OKLAHOMA CITY, OK 28414","dot":"768616","ph":"(268) 326-3509","sups":['BARBARA TAYLOR', 'SUSAN MILLER', 'KAREN TAYLOR']},
    {"name":"XPO EXPRESS INC","addr":"4777 Southpoint Dr, MCALLEN, TX 54330","dot":"527540","ph":"(829) 743-2789","sups":['MARIA MARTINEZ', 'JOSEPH HARRIS', 'PATRICIA WHITE']},
    {"name":"FREIGHT PIONEER SHIPPING CO","addr":"1453 Business Center Dr, DES MOINES, IA 94773","dot":"2270117","ph":"(413) 522-5921","sups":['BARBARA LEE', 'SARAH LEWIS', 'CARLOS MARTINEZ']},
    {"name":"ROEHL HAULING CORP","addr":"1995 Eastgate Dr, TULSA, OK 31010","dot":"137065","ph":"(400) 651-8353","sups":['DAVID GARCIA', 'MICHAEL JONES', 'RICHARD GONZALEZ']},
    {"name":"ANDERSON HAULING LLC","addr":"5683 Commerce Dr, SPOKANE, WA 31820","dot":"1672865","ph":"(218) 815-7630","sups":['DAVID JONES', 'JOHN LEWIS', 'BARBARA GARCIA']},
    {"name":"FREIGHT TRANSPORT LP","addr":"3150 Freight Way, FORT WORTH, TX 54830","dot":"3676015","ph":"(243) 229-3577","sups":['MARY GARCIA', 'SARAH MOORE', 'SOFIA MOORE']},
    {"name":"MARTIN SHIPPING LLC","addr":"4121 Corporate Dr, BAKERSFIELD, CA 68956","dot":"3806181","ph":"(863) 550-9891","sups":['MICHAEL TAYLOR', 'LAURA GARCIA', 'SOFIA LOPEZ']},
    {"name":"DAVIS TRUCKING CO LP","addr":"6764 Logistics Blvd, FORT WAYNE, IN 67024","dot":"3347848","ph":"(475) 871-1321","sups":['BARBARA JONES', 'CARLOS DAVIS', 'ROBERT ROBINSON']},
    {"name":"JB HUNT XPO FREIGHTWAYS GROUP LLC","addr":"7688 Westside Dr, BIRMINGHAM, AL 61807","dot":"2135446","ph":"(330) 211-3072","sups":['LUIS LEE', 'CARLOS THOMAS', 'LINDA ANDERSON']},
    {"name":"LEGACY HAULING CO","addr":"6854 Commerce Dr, FRESNO, CA 60527","dot":"1244552","ph":"(238) 209-8395","sups":['JOHN ANDERSON', 'SARAH TAYLOR', 'THOMAS HERNANDEZ']},
    {"name":"ZENITH TRANSPORT LLC LP","addr":"1414 Logistics Blvd, FORT WORTH, TX 37083","dot":"3877986","ph":"(381) 771-4291","sups":['PATRICIA WILSON', 'JOHN MARTINEZ', 'KAREN ANDERSON']},
    {"name":"MIDWEST TRANSPORT LLC CORP","addr":"758 Commerce Dr, TULSA, OK 11929","dot":"423762","ph":"(976) 513-9732","sups":['LAURA JOHNSON', 'JENNIFER WILSON', 'THOMAS MILLER']},
    {"name":"WESTERN FREIGHT SYSTEMS INC","addr":"5464 Park Ave, CHARLOTTE, NC 92291","dot":"3486065","ph":"(278) 967-2049","sups":['MARIA WHITE', 'MICHAEL JACKSON', 'JAMES GONZALEZ']},
    {"name":"JONES TRANSPORT LLC CORP","addr":"5645 Northgate Blvd, EL PASO, TX 86093","dot":"427092","ph":"(778) 608-9075","sups":['ANTONIO TAYLOR', 'JESSICA CLARK', 'THOMAS WHITE']},
    {"name":"FALCON TURNPIKE EXPRESS LLC","addr":"5760 Broad St, LUBBOCK, TX 99153","dot":"2792003","ph":"(594) 367-6844","sups":['THOMAS RAMIREZ', 'ANA MARTINEZ', 'JOSEPH THOMPSON']},
    {"name":"WERNER LOGISTICS LP","addr":"1839 Commerce Dr, EVANSVILLE, IN 52092","dot":"2052595","ph":"(988) 470-9295","sups":['ELIZABETH LOPEZ', 'PATRICIA MARTINEZ', 'MARY WILSON']},
    {"name":"DIAMOND PIONEER LOGISTICS LLC LP","addr":"4422 Broad St, BATON ROUGE, LA 77171","dot":"976644","ph":"(584) 556-2560","sups":['ANA PEREZ', 'CARLOS LEWIS', 'JENNIFER MOORE']},
    {"name":"HIGHWAY ROEHL LINES LP","addr":"2703 Southpoint Dr, DES MOINES, IA 72255","dot":"1478215","ph":"(780) 707-1451","sups":['JESSICA JACKSON', 'JAMES SMITH', 'CHARLES BROWN']},
    {"name":"APEX CARRIERS INC LP","addr":"5508 Enterprise Way, FRESNO, CA 40440","dot":"2477803","ph":"(244) 327-3613","sups":['RICHARD THOMAS', 'KAREN MOORE', 'CARLOS WILLIAMS']},
    {"name":"TURNPIKE SUMMIT FREIGHT INC","addr":"9675 Cargo Way, JOPLIN, MO 49564","dot":"1309429","ph":"(924) 632-9912","sups":['LINDA WILLIAMS', 'PATRICIA ROBINSON', 'JOSEPH SMITH']},
    {"name":"PINNACLE TRAIL BLAZER TRANSPORT SERVICES LLC","addr":"7224 Terminal Rd, CHATTANOOGA, TN 90873","dot":"1377916","ph":"(876) 999-2034","sups":['JOHN HERNANDEZ', 'MARY LEE', 'SUSAN HARRIS']},
    {"name":"WHITE HAULING INC","addr":"9460 Trucking Ln, BIRMINGHAM, AL 58081","dot":"582078","ph":"(561) 733-7201","sups":['JOSE DAVIS', 'JOSEPH JONES', 'MICHAEL HARRIS']},
    {"name":"FREEDOM LOGISTICS LLC INC","addr":"1492 Eastgate Dr, LUBBOCK, TX 72126","dot":"2761306","ph":"(611) 254-4625","sups":['BARBARA HARRIS', 'ANTONIO HERNANDEZ', 'BARBARA LOPEZ']},
    {"name":"GARCIA HAULING ENTERPRISES LLC","addr":"3848 Industrial Pkwy, BAKERSFIELD, CA 41970","dot":"1056603","ph":"(955) 808-8279","sups":['JESSICA SMITH', 'JAMES THOMPSON', 'MIGUEL JACKSON']},
    {"name":"SUMMIT EXPRESS CO","addr":"4535 Park Ave, SAN ANTONIO, TX 31172","dot":"3049008","ph":"(915) 233-6246","sups":['JOSE WILSON', 'CHARLES WHITE', 'ROBERT LOPEZ']},
    {"name":"HIGHWAY TRANSPORT LLC GROUP LLC","addr":"3138 Business Center Dr, LITTLE ROCK, AR 57406","dot":"1553878","ph":"(960) 905-3185","sups":['LINDA ANDERSON', 'JOHN GARCIA', 'RICHARD ROBINSON']},
    {"name":"GONZALEZ TRUCKING LLC","addr":"356 Airport Rd, SAN ANTONIO, TX 37005","dot":"2525459","ph":"(238) 255-6619","sups":['LINDA BROWN', 'JESSICA MARTINEZ', 'CHARLES SMITH']},
    {"name":"PHOENIX LINES LLC","addr":"7362 Distribution Center Rd, BOISE, ID 27945","dot":"3674499","ph":"(341) 780-8399","sups":['ELIZABETH THOMPSON', 'SUSAN SMITH', 'ANA THOMAS']},
    {"name":"NATIONAL INDEPENDENCE LOGISTICS LLC HOLDINGS INC","addr":"4148 Eastgate Dr, FORT WAYNE, IN 39918","dot":"3428845","ph":"(838) 953-1866","sups":['SOFIA HARRIS', 'SARAH TAYLOR', 'PATRICIA ROBINSON']},
    {"name":"KNIGHT LOGISTICS LLC","addr":"1003 Business Center Dr, JOPLIN, MO 22541","dot":"159529","ph":"(338) 304-5029","sups":['JAMES CLARK', 'CHARLES LOPEZ', 'BARBARA RODRIGUEZ']},
    {"name":"GREEN VALLEY TRUCKING LP","addr":"3735 Airport Rd, WICHITA, KS 80094","dot":"2462659","ph":"(378) 397-8740","sups":['WILLIAM MILLER', 'ANTONIO JONES', 'MARIA SMITH']},
    {"name":"LIBERTY BELL SYNERGY TRANSPORTATION CORP","addr":"854 Westside Dr, TULSA, OK 22089","dot":"1035706","ph":"(617) 654-2543","sups":['LINDA JACKSON', 'LINDA MARTINEZ', 'JAMES MARTINEZ']},
    {"name":"EASTERN LOGISTICS LLC CO","addr":"7190 Eastgate Dr, AKRON, OH 51222","dot":"1182364","ph":"(807) 925-5711","sups":['CHARLES RODRIGUEZ', 'KAREN MILLER', 'ANA THOMPSON']},
    {"name":"MARTEN SWIFT FREIGHT LLC","addr":"9692 Park Ave, MCALLEN, TX 96134","dot":"3045960","ph":"(654) 833-5475","sups":['ANTONIO LEE', 'DIANA TAYLOR', 'JOHN MOORE']},
    {"name":"LIBERTY HORIZON LOGISTICS LLC CO","addr":"4387 Airport Rd, JOPLIN, MO 31875","dot":"598775","ph":"(247) 400-3577","sups":['ROBERT PEREZ', 'BARBARA THOMPSON', 'DAVID WILLIAMS']},
    {"name":"SYNERGY TRUCKING CO INC","addr":"1450 Enterprise Way, DENVER, CO 28828","dot":"2874963","ph":"(539) 671-5869","sups":['ANTONIO HARRIS', 'KAREN PEREZ', 'BARBARA MOORE']},
    {"name":"HIGHWAY CARRIERS INC LP","addr":"4066 Freight Way, SAN ANTONIO, TX 41379","dot":"1616099","ph":"(430) 464-8137","sups":['JENNIFER HARRIS', 'MICHAEL MARTIN', 'KAREN SMITH']},
    {"name":"PRIME LOAD STAR CARRIERS ENTERPRISES LLC","addr":"7784 Terminal Rd, AKRON, OH 96385","dot":"2467030","ph":"(553) 566-5608","sups":['BARBARA RODRIGUEZ', 'DIANA THOMAS', 'CARLOS MARTIN']},
    {"name":"MOORE LOGISTICS ENTERPRISES LLC","addr":"8137 Southpoint Dr, PORTLAND, OR 93791","dot":"1420780","ph":"(852) 386-2683","sups":['JAMES WHITE', 'PATRICIA SMITH', 'SUSAN MOORE']},
    {"name":"EXPRESS CARRIERS INC LLC","addr":"6196 Freight Way, PORTLAND, OR 55555","dot":"2516922","ph":"(878) 445-3993","sups":['PATRICIA TAYLOR', 'SARAH WILLIAMS', 'CHARLES LEE']},
    {"name":"CATALYST HAULING LLC","addr":"1986 Main St, SPRINGFIELD, MO 23970","dot":"2549331","ph":"(779) 574-6193","sups":['JOSEPH LEWIS', 'SUSAN MARTINEZ', 'MARIA WILLIAMS']},
    {"name":"VELOCITY LOGISTICS INC","addr":"8372 Industrial Way, LAS VEGAS, NV 75578","dot":"3533584","ph":"(667) 307-2126","sups":['CHARLES MARTINEZ', 'DIANA WHITE', 'CHARLES BROWN']},
    {"name":"HERITAGE NATIONAL FREIGHT SYSTEMS HOLDINGS INC","addr":"4548 Industrial Way, FORT WORTH, TX 91530","dot":"2976496","ph":"(626) 482-7095","sups":['JOHN THOMAS', 'MARIA LOPEZ', 'DIANA MILLER']},
    {"name":"CONTINENTAL TRANSPORTATION LP","addr":"4100 Park Ave, RICHMOND, VA 77834","dot":"346122","ph":"(482) 201-2439","sups":['SARAH CLARK', 'MIGUEL DAVIS', 'THOMAS CLARK']},
    {"name":"VELOCITY MOUNTAIN CARRIERS INC HOLDINGS INC","addr":"254 Cargo Way, TOLEDO, OH 70000","dot":"2219346","ph":"(461) 825-2733","sups":['CARLOS RODRIGUEZ', 'SUSAN TAYLOR', 'JOHN ROBINSON']},
    {"name":"COAST TO COAST CARRIERS INC CO","addr":"7076 Trucking Ln, OMAHA, NE 82790","dot":"3845278","ph":"(751) 528-8082","sups":['LUIS WILLIAMS', 'CARLOS JOHNSON', 'SOFIA JONES']},
    {"name":"HEARTLAND FREIGHT SYSTEMS ENTERPRISES LLC","addr":"8083 Cargo Way, EVANSVILLE, IN 95534","dot":"520809","ph":"(944) 647-2686","sups":['SUSAN TAYLOR', 'JOSE HERNANDEZ', 'CARLOS ANDERSON']},
    {"name":"LEGACY CARGO TRUCKING GROUP LLC","addr":"8129 Northgate Blvd, CHICAGO, IL 79146","dot":"633877","ph":"(957) 649-6996","sups":['JENNIFER LEE', 'LINDA MOORE', 'DIANA RODRIGUEZ']},
    {"name":"DESERT TRANSPORTATION INC","addr":"351 Eastgate Dr, DAYTON, OH 98739","dot":"3534100","ph":"(552) 547-2396","sups":['CARLOS SANCHEZ', 'CHARLES LOPEZ', 'MICHAEL JOHNSON']},
    {"name":"EXPRESS TRUCKING CO","addr":"313 Industrial Way, CHARLOTTE, NC 27117","dot":"545926","ph":"(580) 851-2960","sups":['ROBERT DAVIS', 'LINDA LEE', 'MARY MOORE']},
    {"name":"TRANS HAULING LP","addr":"2740 Corporate Dr, CORPUS CHRISTI, TX 14359","dot":"3653907","ph":"(302) 472-1366","sups":['LINDA CLARK', 'SUSAN MILLER', 'LAURA TAYLOR']},
    {"name":"GOLD LOGISTICS LLC LLC","addr":"3263 Corporate Dr, RENO, NV 85292","dot":"2709349","ph":"(739) 894-2451","sups":['SARAH DAVIS', 'ANA LEE', 'JAMES HARRIS']},
    {"name":"CATALYST FREIGHT LP","addr":"6457 Freight Way, BOISE, ID 95275","dot":"436072","ph":"(765) 319-4945","sups":['SOFIA THOMAS', 'DIANA HARRIS', 'SUSAN WILSON']},
    {"name":"WESTERN LOGISTICS ENTERPRISES LLC","addr":"9005 Commerce Dr, LAREDO, TX 84191","dot":"3675926","ph":"(632) 913-6462","sups":['KAREN ROBINSON', 'JOSEPH WHITE', 'CHARLES ANDERSON']},
    {"name":"SUMMIT LINES CORP","addr":"6889 Park Ave, OKLAHOMA CITY, OK 10132","dot":"2401098","ph":"(469) 412-6426","sups":['SUSAN MARTINEZ', 'BARBARA JACKSON', 'CHARLES RAMIREZ']},
    {"name":"LIBERTY BELL NORTHERN LOGISTICS LLC HOLDINGS INC","addr":"5927 Fleet St, OKLAHOMA CITY, OK 62442","dot":"3225963","ph":"(436) 328-7027","sups":['THOMAS GARCIA', 'DIANA LEE', 'JAMES JOHNSON']},
    {"name":"DIAMOND SHIPPING CORP","addr":"3843 Westside Dr, LANSING, MI 68929","dot":"3403577","ph":"(295) 889-7797","sups":['JOSEPH GARCIA', 'PATRICIA MILLER', 'ELIZABETH PEREZ']},
    {"name":"COAST TO COAST HAULING CORP","addr":"6300 Eastgate Dr, CHATTANOOGA, TN 42810","dot":"2586007","ph":"(893) 730-7482","sups":['THOMAS ANDERSON', 'SUSAN RAMIREZ', 'WILLIAM JOHNSON']},
    {"name":"XPO FREIGHT SYSTEMS CO","addr":"7880 Westside Dr, SALT LAKE CITY, UT 13729","dot":"1248014","ph":"(558) 485-4636","sups":['LUIS PEREZ', 'RICHARD DAVIS', 'MARY WILSON']},
    {"name":"LAKESIDE HAULING CORP","addr":"8849 Northgate Blvd, LOUISVILLE, KY 26468","dot":"1248690","ph":"(383) 449-1066","sups":['MARIA CLARK', 'CHARLES MARTIN', 'SARAH THOMAS']},
    {"name":"STERLING HEARTLAND FREIGHTWAYS CORP","addr":"7259 Freight Way, EVANSVILLE, IN 67064","dot":"2271394","ph":"(536) 311-9596","sups":['ANTONIO ROBINSON', 'MIGUEL CLARK', 'DAVID MARTIN']},
    {"name":"ROBINSON EXPRESS CO","addr":"501 Business Center Dr, CHARLOTTE, NC 25777","dot":"1819293","ph":"(425) 719-1107","sups":['MIGUEL THOMAS', 'KAREN PEREZ', 'JENNIFER LEE']},
    {"name":"INDEPENDENCE HAWK FREIGHTWAYS LLC","addr":"5051 Freight Way, ATLANTA, GA 45561","dot":"2142380","ph":"(597) 374-2394","sups":['JOHN ROBINSON', 'KAREN LEWIS', 'SOFIA DAVIS']},
    {"name":"FOUNDERS FREIGHT SYSTEMS HOLDINGS INC","addr":"118 Commerce Dr, HOUSTON, TX 87099","dot":"2853764","ph":"(258) 701-5610","sups":['WILLIAM PEREZ', 'THOMAS THOMAS', 'LUIS SANCHEZ']},
    {"name":"THOMAS FREIGHT CORP","addr":"8435 Park Ave, COLUMBUS, OH 60934","dot":"907755","ph":"(280) 514-4128","sups":['LINDA LOPEZ', 'MIGUEL THOMAS', 'CARLOS THOMAS']},
    {"name":"MOMENTUM CARRIERS INC ENTERPRISES LLC","addr":"7467 Eastgate Dr, EL PASO, TX 24115","dot":"310864","ph":"(258) 971-5469","sups":['DIANA LEWIS', 'DIANA JACKSON', 'ROBERT MARTIN']},
    {"name":"ROEHL TRANSPORT LLC LLC","addr":"5606 Westside Dr, OMAHA, NE 48056","dot":"1405952","ph":"(937) 283-9932","sups":['ELIZABETH MILLER', 'JOSE LOPEZ', 'MARIA MARTIN']},
    {"name":"HEARTLAND HERITAGE TRANSPORT CO","addr":"3199 Park Ave, DES MOINES, IA 96455","dot":"3087849","ph":"(794) 939-4491","sups":['KAREN MILLER', 'MARY LEWIS', 'ANTONIO LEWIS']},
    {"name":"GREEN VALLEY NORTHERN EXPRESS ENTERPRISES LLC","addr":"6360 Depot St, SEATTLE, WA 18327","dot":"108729","ph":"(327) 605-8879","sups":['PATRICIA HERNANDEZ', 'JOHN SMITH', 'JOHN CLARK']},
    {"name":"FRONTIER LINES GROUP LLC","addr":"4832 Business Center Dr, SPRINGFIELD, MO 67410","dot":"2794466","ph":"(241) 829-5544","sups":['DIANA THOMPSON', 'SOFIA MOORE', 'JOHN DAVIS']},
    {"name":"VANGUARD TRANSPORTATION LP","addr":"6601 Logistics Blvd, GRAND RAPIDS, MI 28838","dot":"531646","ph":"(484) 464-8625","sups":['ANTONIO LOPEZ', 'JESSICA LEE', 'JOHN CLARK']},
    {"name":"TURNPIKE BLUE SKY FREIGHT CORP","addr":"9100 Logistics Blvd, INDIANAPOLIS, IN 57019","dot":"1564356","ph":"(812) 383-7427","sups":['JAMES RODRIGUEZ', 'SARAH DAVIS', 'CHARLES BROWN']},
    {"name":"SOUTHERN FREIGHT SYSTEMS ENTERPRISES LLC","addr":"2433 Terminal Rd, LOUISVILLE, KY 84645","dot":"1494218","ph":"(711) 568-1637","sups":['LUIS LEE', 'JENNIFER RAMIREZ', 'CHARLES CLARK']},
    {"name":"ROEHL CARGO MASTER TRUCKING CO","addr":"6504 Industrial Pkwy, DENVER, CO 49685","dot":"1095607","ph":"(302) 357-1544","sups":['CHARLES ANDERSON', 'ANA MARTIN', 'JOHN WHITE']},
    {"name":"STAR BLUE SKY CARRIERS GROUP LLC","addr":"4044 Highway Dr, DALLAS, TX 33230","dot":"742639","ph":"(968) 815-6078","sups":['ANTONIO LEWIS', 'SUSAN RODRIGUEZ', 'MARY SMITH']},
    {"name":"WILSON CARRIERS INC","addr":"3553 Southpoint Dr, EL PASO, TX 75698","dot":"1072166","ph":"(455) 908-5473","sups":['RICHARD MARTIN', 'LINDA SANCHEZ', 'DIANA SANCHEZ']},
    {"name":"HERNANDEZ TRUCKING CO LP","addr":"8662 Distribution Center Rd, NASHVILLE, TN 50848","dot":"3166913","ph":"(823) 549-7077","sups":['JENNIFER SMITH', 'KAREN MARTIN', 'JOSEPH JONES']},
    {"name":"XPO GOLD LOGISTICS LLC LP","addr":"9030 Park Ave, LUBBOCK, TX 64637","dot":"105995","ph":"(422) 509-2079","sups":['DIANA LEE', 'DAVID PEREZ', 'RICHARD LEWIS']},
    {"name":"HERITAGE EXPRESS TRUCKING INC","addr":"7380 Freight Way, BATON ROUGE, LA 21563","dot":"2267334","ph":"(375) 786-7129","sups":['LUIS MARTIN', 'ANA ROBINSON', 'SUSAN WILLIAMS']},
    {"name":"ANDERSON TRANSPORT SERVICES LLC","addr":"4683 Fleet St, AUSTIN, TX 17137","dot":"2977885","ph":"(773) 482-8918","sups":['LUIS SANCHEZ', 'JOSE LEE', 'ROBERT LEE']},
    {"name":"RUSH PREMIER LOGISTICS HOLDINGS INC","addr":"508 Trucking Ln, MEMPHIS, TN 82956","dot":"444565","ph":"(279) 619-7974","sups":['SARAH RODRIGUEZ', 'MARIA HERNANDEZ', 'RICHARD PEREZ']},
    {"name":"LIBERTY CARRIERS INC GROUP LLC","addr":"6473 Main St, LAREDO, TX 34264","dot":"854140","ph":"(282) 966-2018","sups":['JOHN LEE', 'ROBERT WHITE', 'ELIZABETH HERNANDEZ']},
    {"name":"PRIME FREIGHT LLC","addr":"7112 Park Ave, AUSTIN, TX 41376","dot":"378990","ph":"(357) 699-5207","sups":['MICHAEL ANDERSON', 'JOHN JOHNSON', 'THOMAS JACKSON']},
    {"name":"WESTERN LOAD STAR LOGISTICS GROUP ENTERPRISES LLC","addr":"5429 Industrial Way, KNOXVILLE, TN 19080","dot":"2047342","ph":"(653) 790-3971","sups":['KAREN MARTINEZ', 'JOSEPH BROWN', 'JOHN SMITH']},
    {"name":"PRIME DIAMOND CARRIERS INC CO","addr":"6380 Highway Dr, BOISE, ID 99698","dot":"3743898","ph":"(773) 477-1592","sups":['CHARLES TAYLOR', 'PATRICIA CLARK', 'WILLIAM HARRIS']},
    {"name":"CONTINENTAL TRUCKING CO","addr":"2928 Southpoint Dr, DES MOINES, IA 44697","dot":"532638","ph":"(928) 696-8733","sups":['MARY JONES', 'JAMES RODRIGUEZ', 'CHARLES RAMIREZ']},
    {"name":"MARTINEZ FREIGHT SYSTEMS GROUP LLC","addr":"1437 Commerce Dr, LITTLE ROCK, AR 81539","dot":"2417540","ph":"(416) 730-8069","sups":['ROBERT MARTIN', 'PATRICIA MOORE', 'SARAH JONES']},
    {"name":"BLUE SKY FREIGHTWAYS INC","addr":"7098 Freight Way, LOUISVILLE, KY 94785","dot":"2669521","ph":"(250) 786-4825","sups":['SUSAN WILSON', 'PATRICIA DAVIS', 'CHARLES JONES']},
    {"name":"RODRIGUEZ LOGISTICS LLC GROUP LLC","addr":"120 Southpoint Dr, ATLANTA, GA 77043","dot":"1062663","ph":"(328) 823-6053","sups":['MARY HERNANDEZ', 'CHARLES GARCIA', 'DIANA PEREZ']},
    {"name":"TRANS INTERSTATE TRUCKING LP","addr":"6939 Northgate Blvd, NASHVILLE, TN 63674","dot":"3688565","ph":"(695) 822-7652","sups":['LUIS ROBINSON', 'CARLOS RODRIGUEZ', 'MIGUEL LEE']},
    {"name":"SILVER LOGISTICS GROUP GROUP LLC","addr":"8210 Commerce Dr, AKRON, OH 79771","dot":"607860","ph":"(334) 296-7609","sups":['LINDA SANCHEZ', 'JAMES LEE', 'CARLOS SANCHEZ']},
    {"name":"JOHNSON LOGISTICS CO","addr":"4333 Industrial Way, CHARLOTTE, NC 40367","dot":"2044690","ph":"(484) 438-3956","sups":['LUIS RODRIGUEZ', 'SOFIA GONZALEZ', 'JESSICA HERNANDEZ']},
    {"name":"USA FREIGHTWAYS LLC","addr":"4999 Depot St, JOPLIN, MO 96293","dot":"2031393","ph":"(829) 217-9436","sups":['LUIS RAMIREZ', 'DIANA MARTINEZ', 'CARLOS GARCIA']},
    {"name":"THOMAS TRANSPORT GROUP LLC","addr":"6194 Logistics Blvd, DES MOINES, IA 89124","dot":"2833298","ph":"(789) 351-2433","sups":['MARY MARTINEZ', 'DIANA JACKSON', 'RICHARD LEE']},
    {"name":"EXPRESS FREIGHT INC","addr":"7342 Logistics Blvd, NASHVILLE, TN 36127","dot":"3841549","ph":"(508) 556-4133","sups":['DIANA ROBINSON', 'SUSAN GONZALEZ', 'SARAH CLARK']},
    {"name":"PACIFIC LOGISTICS HOLDINGS INC","addr":"5073 Trucking Ln, BATON ROUGE, LA 15325","dot":"458595","ph":"(469) 245-3461","sups":['MARIA LOPEZ', 'DIANA LOPEZ', 'LINDA PEREZ']},
    {"name":"PIONEER CARRIERS INC CO","addr":"5800 Airport Rd, EVANSVILLE, IN 74929","dot":"1491725","ph":"(729) 381-3712","sups":['MICHAEL PEREZ', 'JOHN ANDERSON', 'LINDA JACKSON']},
    {"name":"BLUE SKY TRUCKING CO HOLDINGS INC","addr":"2590 Industrial Way, AUSTIN, TX 72869","dot":"2012190","ph":"(344) 560-8247","sups":['PATRICIA THOMPSON', 'JOSE ROBINSON', 'ELIZABETH MOORE']},
    {"name":"DESERT DIAMOND CARRIERS INC GROUP LLC","addr":"9604 Cargo Way, MOBILE, AL 57366","dot":"2482019","ph":"(323) 908-4252","sups":['MIGUEL MARTINEZ', 'JAMES TAYLOR', 'SARAH TAYLOR']},
    {"name":"MARTINEZ HAULING ENTERPRISES LLC","addr":"3332 Westside Dr, RENO, NV 60442","dot":"3991280","ph":"(893) 708-6684","sups":['RICHARD JOHNSON', 'WILLIAM CLARK', 'JOSEPH BROWN']},
    {"name":"ZENITH TRUCKING CO CORP","addr":"1340 Trucking Ln, HOUSTON, TX 24412","dot":"1610484","ph":"(442) 652-2586","sups":['JAMES ROBINSON', 'BARBARA GONZALEZ', 'THOMAS WILSON']},
    {"name":"TURNPIKE FREIGHTWAYS GROUP LLC","addr":"7034 Fleet St, CORPUS CHRISTI, TX 70425","dot":"480801","ph":"(350) 336-9855","sups":['SOFIA CLARK', 'MICHAEL JOHNSON', 'LUIS SANCHEZ']},
    {"name":"CLARK HAULING CO","addr":"8369 Industrial Way, SAN ANTONIO, TX 23588","dot":"1351074","ph":"(286) 325-1282","sups":['JOSEPH CLARK', 'CARLOS JONES', 'JOSE PEREZ']},
    {"name":"SYNERGY LINES INC","addr":"4133 Westside Dr, WICHITA, KS 31625","dot":"3085766","ph":"(665) 318-3071","sups":['JAMES ANDERSON', 'ELIZABETH JACKSON', 'THOMAS LEWIS']},
    {"name":"TRANS CROWN EXPRESS ENTERPRISES LLC","addr":"9213 Distribution Center Rd, LOUISVILLE, KY 88183","dot":"3911504","ph":"(547) 571-8585","sups":['MARIA TAYLOR', 'PATRICIA SANCHEZ', 'JOSE HARRIS']},
    {"name":"SYNERGY FREEDOM FREIGHTWAYS CO","addr":"5773 Industrial Way, SPOKANE, WA 84503","dot":"2207550","ph":"(519) 469-8337","sups":['RICHARD RODRIGUEZ', 'ANA HARRIS', 'DAVID DAVIS']},
    {"name":"NEXUS LOGISTICS GROUP INC","addr":"4736 Corporate Dr, GRAND RAPIDS, MI 78249","dot":"772255","ph":"(249) 757-1972","sups":['MIGUEL MOORE', 'SARAH PEREZ', 'ELIZABETH THOMPSON']},
    {"name":"ZENITH XPO TRANSPORT ENTERPRISES LLC","addr":"9508 Distribution Center Rd, OMAHA, NE 54483","dot":"743817","ph":"(355) 503-9003","sups":['ROBERT SMITH', 'BARBARA TAYLOR', 'WILLIAM HERNANDEZ']},
    {"name":"VANGUARD CONTINENTAL FREIGHT HOLDINGS INC","addr":"4545 Industrial Pkwy, COLUMBUS, OH 12909","dot":"2199682","ph":"(874) 215-3421","sups":['JOSE RAMIREZ', 'BARBARA WILLIAMS', 'SARAH JOHNSON']},
    {"name":"LOPEZ TRANSPORT HOLDINGS INC","addr":"8190 Industrial Way, COLUMBUS, OH 64410","dot":"3876561","ph":"(367) 635-1239","sups":['PATRICIA RODRIGUEZ', 'MICHAEL ROBINSON', 'LUIS RODRIGUEZ']},
    {"name":"STERLING CROSS COUNTRY LOGISTICS LLC CORP","addr":"5707 Trucking Ln, COLUMBUS, OH 37226","dot":"2861595","ph":"(314) 469-8767","sups":['ANTONIO PEREZ', 'ANA MOORE', 'SOFIA DAVIS']},
    {"name":"MIDWEST HEARTLAND FREIGHT SYSTEMS ENTERPRISES LLC","addr":"5720 Eastgate Dr, AUSTIN, TX 68583","dot":"2063702","ph":"(630) 728-5113","sups":['MIGUEL GARCIA', 'MARIA RAMIREZ', 'JESSICA LEWIS']},
    {"name":"APEX SYNERGY TRANSPORT LLC INC","addr":"2792 Depot St, SPOKANE, WA 28124","dot":"1870466","ph":"(716) 868-6372","sups":['JESSICA BROWN', 'JESSICA PEREZ', 'JOSE JOHNSON']},
    {"name":"ANDERSON FREIGHT HOLDINGS INC","addr":"3168 Main St, NASHVILLE, TN 71425","dot":"3881484","ph":"(697) 378-5304","sups":['SOFIA RAMIREZ', 'MIGUEL MILLER', 'DAVID JOHNSON']},
    {"name":"LEWIS TRANSPORT SERVICES CORP","addr":"9414 Broad St, EVANSVILLE, IN 57674","dot":"3171825","ph":"(214) 432-9792","sups":['JENNIFER BROWN', 'MARIA HARRIS', 'ELIZABETH LEWIS']},
    {"name":"SWIFT TRANSPORT SERVICES INC","addr":"7297 Industrial Pkwy, OMAHA, NE 30175","dot":"1565220","ph":"(701) 690-5370","sups":['JAMES JONES', 'WILLIAM TAYLOR', 'DIANA MOORE']},
    {"name":"NEXUS FREIGHT CORP","addr":"881 Distribution Center Rd, MCALLEN, TX 12425","dot":"2727659","ph":"(413) 957-9313","sups":['LUIS ANDERSON', 'MARIA MILLER', 'LUIS WHITE']},
    {"name":"INDEPENDENCE MOUNTAIN TRANSPORT SERVICES LP","addr":"7298 Distribution Center Rd, DAYTON, OH 90819","dot":"244457","ph":"(412) 233-7630","sups":['ANA MILLER', 'ELIZABETH THOMPSON', 'JAMES MOORE']},
    {"name":"SUMMIT TRUCKING CO INC","addr":"9065 Eastgate Dr, PHOENIX, AZ 24077","dot":"540248","ph":"(756) 996-6368","sups":['LINDA TAYLOR', 'LAURA JONES', 'WILLIAM JACKSON']},
    {"name":"TAYLOR TRANSPORT LLC LLC","addr":"4498 Broad St, LITTLE ROCK, AR 42924","dot":"1918597","ph":"(557) 885-9918","sups":['LAURA MARTINEZ', 'JAMES SMITH', 'SOFIA ROBINSON']},
    {"name":"INDEPENDENCE LOGISTICS GROUP LLC","addr":"8025 Cargo Way, COLUMBUS, OH 68813","dot":"1979522","ph":"(485) 973-7817","sups":['SARAH ANDERSON', 'LINDA WHITE', 'CARLOS ANDERSON']},
    {"name":"FREIGHT AMERICAN FREIGHTWAYS HOLDINGS INC","addr":"9483 Cargo Way, GRAND RAPIDS, MI 69302","dot":"2501336","ph":"(338) 289-7744","sups":['SARAH JONES', 'MARY RODRIGUEZ', 'JAMES LEE']},
    {"name":"STEEL CARRIERS INC LP","addr":"1660 Highway Dr, ATLANTA, GA 35413","dot":"2423653","ph":"(692) 784-2460","sups":['JOHN LEE', 'ROBERT JONES', 'LUIS ANDERSON']},
    {"name":"EAGLE TRUCKING CORP","addr":"535 Terminal Rd, LITTLE ROCK, AR 92811","dot":"1255638","ph":"(222) 876-8959","sups":['JOHN RAMIREZ', 'JESSICA ANDERSON', 'MARIA GONZALEZ']},
    {"name":"APEX INDEPENDENCE CARRIERS LP","addr":"6631 Freight Way, MONTGOMERY, AL 38873","dot":"3751888","ph":"(589) 750-6465","sups":['PATRICIA RODRIGUEZ', 'JOSE LEE', 'JENNIFER CLARK']},
    {"name":"PATRIOT CROSS COUNTRY TRANSPORT SERVICES HOLDINGS INC","addr":"9230 Broad St, WICHITA, KS 98654","dot":"162683","ph":"(250) 515-9260","sups":['MARIA WHITE', 'ELIZABETH BROWN', 'ROBERT RAMIREZ']},
    {"name":"GOLD FREIGHT CO","addr":"7635 Airport Rd, FORT WORTH, TX 98991","dot":"3991047","ph":"(531) 237-8033","sups":['ANTONIO RAMIREZ', 'CHARLES BROWN', 'JOSE ANDERSON']},
    {"name":"WILSON TRANSPORT LP","addr":"9515 Fleet St, BOISE, ID 54567","dot":"392538","ph":"(472) 254-6509","sups":['SARAH THOMAS', 'JOSEPH MARTINEZ', 'SOFIA PEREZ']},
    {"name":"MARTIN FREIGHT SYSTEMS CORP","addr":"1787 Industrial Way, DALLAS, TX 49237","dot":"2965607","ph":"(632) 855-3816","sups":['WILLIAM HERNANDEZ', 'CARLOS RAMIREZ', 'JOSEPH SMITH']},
    {"name":"PHOENIX CARGO SHIPPING CORP","addr":"9776 Enterprise Way, MCALLEN, TX 77154","dot":"3528136","ph":"(467) 924-3801","sups":['MIGUEL MILLER', 'THOMAS ROBINSON', 'CHARLES TAYLOR']},
    {"name":"APEX TRANSPORT CO","addr":"2500 Westside Dr, SPOKANE, WA 59132","dot":"3157171","ph":"(361) 942-2515","sups":['JESSICA LOPEZ', 'LINDA HARRIS', 'MARY LEE']},
    {"name":"RODRIGUEZ TRANSPORT SERVICES LP","addr":"8493 Southpoint Dr, KANSAS CITY, MO 36467","dot":"3828940","ph":"(973) 858-6457","sups":['CARLOS RODRIGUEZ', 'CHARLES ANDERSON', 'RICHARD ANDERSON']},
    {"name":"SCHNEIDER TRANSPORT SERVICES LLC","addr":"6899 Industrial Way, LAS VEGAS, NV 48384","dot":"342323","ph":"(483) 393-9667","sups":['JOHN SMITH', 'BARBARA THOMPSON', 'JAMES CLARK']},
    {"name":"THOMPSON CARRIERS INC CO","addr":"6944 Freight Way, CHARLOTTE, NC 90326","dot":"1338165","ph":"(367) 253-2395","sups":['WILLIAM WILSON', 'LUIS TAYLOR', 'MICHAEL WILSON']},
    {"name":"DESERT TRANSPORT SERVICES INC","addr":"8436 Depot St, ALBUQUERQUE, NM 88520","dot":"2456464","ph":"(619) 271-1795","sups":['LINDA MILLER', 'LUIS WILLIAMS', 'JOHN WILLIAMS']},
    {"name":"SANCHEZ TRANSPORT INC","addr":"616 Enterprise Way, CHATTANOOGA, TN 97160","dot":"1310065","ph":"(916) 613-6452","sups":['JESSICA LEWIS', 'CARLOS HARRIS', 'JENNIFER HARRIS']},
    {"name":"UNITED FRONTIER FREIGHTWAYS ENTERPRISES LLC","addr":"2697 Fleet St, DENVER, CO 45179","dot":"1941925","ph":"(332) 414-7343","sups":['MIGUEL CLARK', 'SOFIA ROBINSON', 'ANTONIO RAMIREZ']},
    {"name":"LIBERTY BELL LOGISTICS LP","addr":"7679 Commerce Dr, LAREDO, TX 11982","dot":"2854014","ph":"(419) 861-7194","sups":['JOSE GONZALEZ', 'BARBARA JACKSON', 'MARY WHITE']},
    {"name":"STAR TRANSPORT LLC CO","addr":"7611 Eastgate Dr, OKLAHOMA CITY, OK 29461","dot":"270649","ph":"(620) 644-3558","sups":['LAURA GONZALEZ', 'CARLOS SANCHEZ', 'SARAH JOHNSON']},
    {"name":"BROWN TRANSPORTATION LLC","addr":"2257 Fleet St, OMAHA, NE 88482","dot":"3147894","ph":"(206) 295-3149","sups":['JOSEPH RODRIGUEZ', 'ANTONIO HERNANDEZ', 'WILLIAM HARRIS']},
    {"name":"INTERSTATE TRANSPORTATION ENTERPRISES LLC","addr":"7647 Industrial Pkwy, MILWAUKEE, WI 18532","dot":"3670110","ph":"(203) 577-3636","sups":['MARIA WILSON', 'SOFIA RAMIREZ', 'MARIA JACKSON']},
    {"name":"SCHNEIDER CARRIERS ENTERPRISES LLC","addr":"1021 Park Ave, CHARLOTTE, NC 47414","dot":"2612462","ph":"(978) 900-5983","sups":['BARBARA SMITH', 'SARAH RODRIGUEZ', 'MIGUEL GARCIA']},
    {"name":"INDEPENDENCE CARRIERS LLC","addr":"253 Cargo Way, LAREDO, TX 49284","dot":"2679540","ph":"(612) 303-3101","sups":['JOHN LEWIS', 'ELIZABETH MARTINEZ', 'CARLOS THOMPSON']},
    {"name":"VELOCITY STERLING TRUCKING LLC","addr":"9967 Park Ave, MCALLEN, TX 70217","dot":"975575","ph":"(718) 898-7334","sups":['LINDA WILSON', 'JENNIFER CLARK', 'BARBARA ROBINSON']},
    {"name":"WILSON CARRIERS INC LLC","addr":"6752 Trucking Ln, SPOKANE, WA 79993","dot":"3837350","ph":"(276) 831-3754","sups":['SARAH GARCIA', 'SOFIA MOORE', 'SOFIA JONES']},
    {"name":"RAMIREZ TRANSPORT CORP","addr":"1201 Commerce Dr, ALBUQUERQUE, NM 69210","dot":"1885772","ph":"(664) 963-5926","sups":['SOFIA LEE', 'JOSEPH GARCIA', 'RICHARD MOORE']},
    {"name":"PINNACLE ESTES FREIGHTWAYS GROUP LLC","addr":"2407 Business Center Dr, ATLANTA, GA 52555","dot":"1818795","ph":"(666) 261-5109","sups":['THOMAS MILLER', 'WILLIAM WILSON', 'SUSAN RODRIGUEZ']},
    {"name":"SCHNEIDER EXPRESS CORP","addr":"1959 Park Ave, AUSTIN, TX 88820","dot":"2839421","ph":"(664) 210-1557","sups":['LUIS CLARK', 'DIANA WILLIAMS', 'ROBERT SMITH']},
    {"name":"HARRIS TRANSPORT CO","addr":"2240 Trucking Ln, TOLEDO, OH 79362","dot":"2483528","ph":"(877) 325-9740","sups":['KAREN SANCHEZ', 'MARIA LEWIS', 'ANA HERNANDEZ']},
    {"name":"EXPRESS PINNACLE LINES INC","addr":"7705 Southpoint Dr, DENVER, CO 81907","dot":"1054722","ph":"(433) 336-9459","sups":['MARY BROWN', 'RICHARD RODRIGUEZ', 'SUSAN JONES']},
    {"name":"SANCHEZ TRANSPORT SERVICES LLC","addr":"4601 Broad St, SHREVEPORT, LA 72651","dot":"2023035","ph":"(722) 917-9428","sups":['ANTONIO ROBINSON', 'JOSE HERNANDEZ', 'JESSICA WILLIAMS']},
    {"name":"THOMAS EXPRESS HOLDINGS INC","addr":"5683 Enterprise Way, MILWAUKEE, WI 34652","dot":"2280044","ph":"(892) 890-1717","sups":['THOMAS BROWN', 'KAREN LOPEZ', 'JOSEPH GONZALEZ']},
    {"name":"DIAMOND BIG RIG CARRIERS INC HOLDINGS INC","addr":"811 Broad St, INDIANAPOLIS, IN 99468","dot":"2338542","ph":"(559) 853-8187","sups":['DAVID LEE', 'LUIS JONES', 'CHARLES GARCIA']},
    {"name":"DIAMOND HAULING ENTERPRISES LLC","addr":"9553 Cargo Way, SPRINGFIELD, MO 80869","dot":"3181355","ph":"(321) 213-7407","sups":['WILLIAM BROWN', 'LINDA DAVIS', 'JAMES GARCIA']},
    {"name":"MILLER LOGISTICS LLC HOLDINGS INC","addr":"8710 Southpoint Dr, SPRINGFIELD, MO 37567","dot":"1485827","ph":"(612) 240-6998","sups":['DAVID MOORE', 'JOSE BROWN', 'BARBARA JACKSON']},
    {"name":"CROSS COUNTRY TRUCKING CO ENTERPRISES LLC","addr":"6045 Terminal Rd, NASHVILLE, TN 33041","dot":"1042390","ph":"(943) 235-8569","sups":['MARY BROWN', 'LUIS MOORE', 'MIGUEL JONES']},
    {"name":"WERNER SWIFT LOGISTICS GROUP LLC","addr":"9324 Enterprise Way, CORPUS CHRISTI, TX 41591","dot":"1502032","ph":"(827) 563-9573","sups":['WILLIAM JACKSON', 'ANA MARTINEZ', 'LINDA CLARK']},
    {"name":"IRON TRANSPORT SERVICES ENTERPRISES LLC","addr":"6675 Westside Dr, JOPLIN, MO 68235","dot":"1842615","ph":"(427) 800-4241","sups":['SARAH CLARK', 'RICHARD WILSON', 'BARBARA MOORE']},
    {"name":"MARTEN CARGO MASTER CARRIERS INC","addr":"7913 Logistics Blvd, BATON ROUGE, LA 26525","dot":"2371504","ph":"(332) 712-5802","sups":['PATRICIA HERNANDEZ', 'RICHARD MARTIN', 'BARBARA THOMAS']},
    {"name":"MOMENTUM TRANSPORTATION GROUP LLC","addr":"7089 Freight Way, COLUMBIA, SC 59744","dot":"3699979","ph":"(535) 832-8792","sups":['ROBERT ROBINSON', 'WILLIAM RAMIREZ', 'RICHARD MOORE']},
    {"name":"LOAD STAR TRANSPORT SERVICES ENTERPRISES LLC","addr":"7117 Park Ave, PHOENIX, AZ 46876","dot":"2774642","ph":"(448) 599-9456","sups":['LUIS GARCIA', 'LINDA WILSON', 'ANTONIO HARRIS']},
    {"name":"ROAD KING COASTAL FREIGHTWAYS GROUP LLC","addr":"3256 Logistics Blvd, MCALLEN, TX 58764","dot":"3476681","ph":"(276) 859-6956","sups":['JESSICA MILLER', 'SARAH CLARK', 'JENNIFER CLARK']},
    {"name":"GONZALEZ FREIGHTWAYS HOLDINGS INC","addr":"774 Enterprise Way, MILWAUKEE, WI 42329","dot":"2365390","ph":"(920) 785-4659","sups":['ROBERT LEE', 'SUSAN GARCIA', 'SUSAN HARRIS']},
    {"name":"RAMIREZ TRUCKING CO HOLDINGS INC","addr":"9659 Fleet St, DENVER, CO 57262","dot":"3228307","ph":"(445) 312-2608","sups":['MIGUEL RAMIREZ', 'MARY WHITE', 'MIGUEL MILLER']},
    {"name":"DIAMOND VELOCITY TRANSPORTATION ENTERPRISES LLC","addr":"3821 Airport Rd, BIRMINGHAM, AL 35917","dot":"3233730","ph":"(861) 548-4715","sups":['BARBARA GARCIA', 'MARIA RAMIREZ', 'JESSICA ROBINSON']},
    {"name":"KNIGHT TRANSPORT SERVICES HOLDINGS INC","addr":"4373 Depot St, GRAND RAPIDS, MI 82775","dot":"3877288","ph":"(304) 405-4592","sups":['ROBERT SANCHEZ', 'PATRICIA WHITE', 'WILLIAM THOMPSON']},
    {"name":"CATALYST TRANSPORT LLC ENTERPRISES LLC","addr":"9199 Business Center Dr, PORTLAND, OR 62401","dot":"3546461","ph":"(924) 338-2920","sups":['LINDA SMITH', 'JOSE THOMAS', 'JOSE LEWIS']},
    {"name":"CATALYST INDEPENDENCE LOGISTICS GROUP INC","addr":"8396 Southpoint Dr, MEMPHIS, TN 21558","dot":"1810346","ph":"(684) 307-5256","sups":['RICHARD ANDERSON', 'JENNIFER CLARK', 'ANA JACKSON']},
    {"name":"HEARTLAND FREIGHT CO","addr":"8701 Main St, DAYTON, OH 12058","dot":"2352597","ph":"(345) 247-4050","sups":['JAMES HERNANDEZ', 'JOSEPH JOHNSON', 'JOSE GARCIA']},
    {"name":"PACIFIC LOGISTICS LLC CORP","addr":"2771 Eastgate Dr, FORT WAYNE, IN 59230","dot":"2279464","ph":"(743) 480-1885","sups":['DIANA ROBINSON', 'KAREN MILLER', 'JOSEPH TAYLOR']},
    {"name":"EAGLE TRANSPORT CORP","addr":"2314 Fleet St, OMAHA, NE 71166","dot":"1534746","ph":"(415) 642-6196","sups":['SARAH CLARK', 'CHARLES HERNANDEZ', 'JESSICA LOPEZ']},
    {"name":"FREIGHT CARRIERS INC LP","addr":"2319 Freight Way, EVANSVILLE, IN 96463","dot":"209758","ph":"(314) 728-5344","sups":['KAREN WILSON', 'ANA LEE', 'MARY THOMPSON']},
    {"name":"LIBERTY BELL CARRIERS INC ENTERPRISES LLC","addr":"2680 Industrial Pkwy, AKRON, OH 25619","dot":"3576461","ph":"(522) 626-9911","sups":['JOHN ROBINSON', 'LUIS LOPEZ', 'JOHN TAYLOR']},
    {"name":"HEARTLAND LOGISTICS GROUP CORP","addr":"6207 Park Ave, FORT WORTH, TX 17208","dot":"118052","ph":"(358) 922-9138","sups":['ANTONIO RODRIGUEZ', 'SARAH SANCHEZ', 'JAMES JACKSON']},
    {"name":"TAYLOR CARRIERS INC","addr":"1164 Westside Dr, LANSING, MI 83725","dot":"2428695","ph":"(927) 282-5464","sups":['SOFIA ANDERSON', 'RICHARD WILSON', 'JENNIFER MARTINEZ']},
    {"name":"WHITE HAULING HOLDINGS INC","addr":"8348 Airport Rd, ALBUQUERQUE, NM 57394","dot":"3927214","ph":"(380) 218-6782","sups":['PATRICIA SANCHEZ', 'ELIZABETH MARTIN', 'LAURA ANDERSON']},
    {"name":"TRANS CARGO MASTER TRANSPORT LLC INC","addr":"2791 Broad St, TULSA, OK 33785","dot":"3507143","ph":"(294) 300-6347","sups":['BARBARA SANCHEZ', 'WILLIAM ANDERSON', 'ROBERT GARCIA']},
    {"name":"LEGACY LAKESIDE SHIPPING INC","addr":"6995 Eastgate Dr, WICHITA, KS 63641","dot":"3856324","ph":"(985) 529-8057","sups":['ROBERT BROWN', 'KAREN RODRIGUEZ', 'ANTONIO BROWN']},
    {"name":"ZENITH CARRIERS LLC","addr":"2883 Business Center Dr, MEMPHIS, TN 69532","dot":"3514162","ph":"(497) 731-7541","sups":['MIGUEL JONES', 'WILLIAM GONZALEZ', 'LUIS MOORE']},
    {"name":"HERITAGE CARRIERS ENTERPRISES LLC","addr":"9607 Westside Dr, SPOKANE, WA 89792","dot":"2980115","ph":"(706) 269-5379","sups":['ELIZABETH WILLIAMS', 'CARLOS HARRIS', 'ROBERT LOPEZ']},
    {"name":"AMERICAN SUMMIT HAULING LP","addr":"2253 Cargo Way, RENO, NV 57696","dot":"2064369","ph":"(945) 375-7733","sups":['CHARLES WHITE', 'JENNIFER ANDERSON', 'DAVID PEREZ']},
    {"name":"FREIGHT PHOENIX TRANSPORT SERVICES CO","addr":"976 Commerce Dr, JACKSON, MS 76062","dot":"3668745","ph":"(971) 985-8085","sups":['LAURA TAYLOR', 'MICHAEL MILLER', 'JOHN LEWIS']},
    {"name":"CATALYST BLUE SKY FREIGHTWAYS LP","addr":"6144 Depot St, SAN ANTONIO, TX 75204","dot":"1606613","ph":"(270) 305-9030","sups":['MARIA JACKSON', 'SOFIA WILSON', 'SUSAN PEREZ']},
    {"name":"EXPRESS TRUCKING HOLDINGS INC","addr":"5220 Business Center Dr, PORTLAND, OR 79507","dot":"113245","ph":"(615) 998-9605","sups":['MIGUEL SMITH', 'MICHAEL MILLER', 'JOSE WHITE']},
    {"name":"PIONEER CARRIERS LLC","addr":"7438 Terminal Rd, SEATTLE, WA 43040","dot":"3144564","ph":"(327) 509-4281","sups":['BARBARA LEWIS', 'KAREN DAVIS', 'THOMAS BROWN']},
    {"name":"LOPEZ TRANSPORT CO","addr":"6357 Broad St, TOLEDO, OH 75843","dot":"1061642","ph":"(710) 617-7670","sups":['JOHN LEWIS', 'SOFIA WILSON', 'JAMES MILLER']},
    {"name":"LAKESIDE GOLD CARRIERS INC ENTERPRISES LLC","addr":"2103 Enterprise Way, COLUMBUS, OH 90207","dot":"530159","ph":"(897) 376-6445","sups":['DIANA CLARK', 'DAVID THOMAS', 'LINDA SANCHEZ']},
    {"name":"ESTES TRANS SHIPPING LLC","addr":"237 Business Center Dr, CHICAGO, IL 26786","dot":"2925483","ph":"(405) 992-8302","sups":['LUIS HERNANDEZ', 'MARIA GONZALEZ', 'JOSEPH DAVIS']},
    {"name":"VELOCITY LOGISTICS LLC HOLDINGS INC","addr":"7537 Enterprise Way, LUBBOCK, TX 93678","dot":"3416071","ph":"(808) 653-3802","sups":['JENNIFER LOPEZ', 'JENNIFER LOPEZ', 'MARIA JACKSON']},
    {"name":"LIBERTY BELL FREIGHTWAYS HOLDINGS INC","addr":"7493 Fleet St, KNOXVILLE, TN 66189","dot":"2421683","ph":"(772) 654-7250","sups":['DIANA RODRIGUEZ', 'LAURA WHITE', 'JOHN PEREZ']},
    {"name":"SCHNEIDER TRANSPORT HOLDINGS INC","addr":"3422 Business Center Dr, SAN ANTONIO, TX 17585","dot":"2154686","ph":"(260) 594-5873","sups":['ROBERT HARRIS', 'JAMES CLARK', 'MARIA BROWN']},
    {"name":"RAMIREZ FREIGHTWAYS CORP","addr":"7825 Corporate Dr, NASHVILLE, TN 10731","dot":"1440375","ph":"(526) 247-5474","sups":['BARBARA CLARK', 'PATRICIA DAVIS', 'JAMES MILLER']},
    {"name":"MARTINEZ SHIPPING INC","addr":"6129 Freight Way, RENO, NV 60053","dot":"960485","ph":"(543) 836-9478","sups":['ANA BROWN', 'JENNIFER THOMPSON', 'LUIS MILLER']},
    {"name":"RUSH LOGISTICS GROUP LLC","addr":"1461 Broad St, SEATTLE, WA 11251","dot":"896199","ph":"(400) 784-9756","sups":['ELIZABETH THOMAS', 'CARLOS ROBINSON', 'BARBARA JONES']},
    {"name":"COVENANT TRANSPORT SERVICES ENTERPRISES LLC","addr":"8025 Main St, HOUSTON, TX 83388","dot":"2948349","ph":"(757) 956-4597","sups":['KAREN TAYLOR', 'KAREN DAVIS', 'LINDA JONES']},
    {"name":"LAKESIDE WESTERN LOGISTICS HOLDINGS INC","addr":"380 Fleet St, OKLAHOMA CITY, OK 14935","dot":"1719570","ph":"(587) 634-1525","sups":['ELIZABETH JACKSON', 'MARIA MARTIN', 'JOSE ROBINSON']},
    {"name":"DAVIS LOGISTICS CO","addr":"6100 Northgate Blvd, FORT WORTH, TX 90929","dot":"2936098","ph":"(308) 411-3860","sups":['ROBERT LEWIS', 'ELIZABETH BROWN', 'MICHAEL MILLER']},
    {"name":"ZENITH FREIGHT TRANSPORTATION ENTERPRISES LLC","addr":"8039 Park Ave, RICHMOND, VA 43752","dot":"3590961","ph":"(498) 821-5320","sups":['JOSE LOPEZ', 'ANTONIO JACKSON', 'MARIA HERNANDEZ']},
    {"name":"APEX LOGISTICS LLC INC","addr":"7922 Broad St, MINNEAPOLIS, MN 44496","dot":"335146","ph":"(304) 964-9334","sups":['LINDA WHITE', 'CARLOS LEE', 'DIANA MOORE']},
    {"name":"ANDERSON TRUCKING CO LP","addr":"7896 Distribution Center Rd, RICHMOND, VA 77117","dot":"226540","ph":"(828) 580-4116","sups":['JOHN HARRIS', 'DAVID DAVIS', 'MIGUEL BROWN']},
    {"name":"PACIFIC HAWK TRUCKING CO","addr":"5534 Trucking Ln, COLUMBUS, OH 43868","dot":"2159968","ph":"(353) 693-1324","sups":['ELIZABETH CLARK', 'BARBARA LOPEZ', 'ELIZABETH LOPEZ']},
    {"name":"ALL AMERICAN LOGISTICS GROUP GROUP LLC","addr":"5865 Airport Rd, FRESNO, CA 38262","dot":"3872505","ph":"(492) 648-4705","sups":['JENNIFER MARTINEZ', 'MARIA HARRIS', 'MIGUEL LEE']},
    {"name":"FREIGHT SHIPPING LLC","addr":"2753 Enterprise Way, GRAND RAPIDS, MI 58180","dot":"3825459","ph":"(856) 205-9157","sups":['MIGUEL MOORE', 'JOHN JACKSON', 'PATRICIA CLARK']},
    {"name":"SUMMIT TURNPIKE TRANSPORT SERVICES CORP","addr":"478 Industrial Pkwy, SAN ANTONIO, TX 24314","dot":"1545904","ph":"(526) 570-6908","sups":['WILLIAM SANCHEZ', 'JAMES CLARK', 'BARBARA WILLIAMS']},
    {"name":"APEX FREIGHTWAYS LP","addr":"741 Trucking Ln, LANSING, MI 40562","dot":"2937925","ph":"(754) 697-6238","sups":['ANA ANDERSON', 'JESSICA MOORE', 'JOSE PEREZ']},
    {"name":"AMERICAN LINES CORP","addr":"4405 Trucking Ln, AKRON, OH 34803","dot":"218658","ph":"(413) 553-7188","sups":['JAMES MARTIN', 'SARAH JACKSON', 'ELIZABETH DAVIS']},
    {"name":"CROSS COUNTRY TRANSPORT LLC ENTERPRISES LLC","addr":"8145 Eastgate Dr, FRESNO, CA 31454","dot":"163694","ph":"(706) 578-5277","sups":['LUIS MARTIN', 'MIGUEL SANCHEZ', 'ANA DAVIS']},
    {"name":"LEGACY TRANSPORT ENTERPRISES LLC","addr":"8229 Airport Rd, TULSA, OK 15455","dot":"2469875","ph":"(792) 252-7091","sups":['DAVID JACKSON', 'LAURA ROBINSON', 'JENNIFER RODRIGUEZ']},
    {"name":"WESTERN LOGISTICS GROUP HOLDINGS INC","addr":"6402 Cargo Way, TOLEDO, OH 80827","dot":"3431241","ph":"(501) 780-5894","sups":['ROBERT RAMIREZ', 'LAURA DAVIS', 'ELIZABETH GARCIA']},
    {"name":"PLAINS FALCON LOGISTICS LLC LP","addr":"5617 Broad St, GRAND RAPIDS, MI 51842","dot":"1958894","ph":"(310) 587-3182","sups":['RICHARD WHITE', 'KAREN JACKSON', 'JOSEPH JOHNSON']},
    {"name":"TITAN SCHNEIDER TRANSPORTATION CO","addr":"880 Westside Dr, LANSING, MI 81067","dot":"418608","ph":"(245) 675-2166","sups":['RICHARD THOMAS', 'SUSAN TAYLOR', 'MIGUEL HERNANDEZ']},
    {"name":"SYNERGY LINES CO","addr":"5478 Industrial Pkwy, TULSA, OK 27154","dot":"3826380","ph":"(379) 855-2181","sups":['LAURA JOHNSON', 'JAMES WHITE', 'JOSEPH MOORE']},
    {"name":"UNITED LINES CORP","addr":"7860 Business Center Dr, RENO, NV 41752","dot":"1953816","ph":"(524) 719-8201","sups":['JOSEPH DAVIS', 'JAMES THOMAS', 'SOFIA RAMIREZ']},
    {"name":"ROAD KING FREIGHT GROUP LLC","addr":"8593 Industrial Way, ALBUQUERQUE, NM 38988","dot":"3715054","ph":"(446) 880-4899","sups":['MICHAEL RAMIREZ', 'LUIS MARTINEZ', 'ELIZABETH PEREZ']},
    {"name":"LEE TRANSPORT GROUP LLC","addr":"6515 Trucking Ln, KNOXVILLE, TN 29812","dot":"3657641","ph":"(599) 515-3980","sups":['ANTONIO PEREZ', 'PATRICIA WILSON', 'JAMES ROBINSON']},
    {"name":"MOORE LINES ENTERPRISES LLC","addr":"4635 Fleet St, SPRINGFIELD, MO 45566","dot":"1829852","ph":"(477) 739-7428","sups":['MIGUEL WILLIAMS', 'MARIA HERNANDEZ', 'JOSE MARTIN']},
    {"name":"WHITE TRANSPORT SERVICES CO","addr":"6742 Airport Rd, BOISE, ID 46708","dot":"124831","ph":"(704) 477-8978","sups":['SUSAN CLARK', 'DIANA MARTIN', 'CHARLES BROWN']},
    {"name":"JOHNSON TRANSPORTATION GROUP LLC","addr":"2598 Westside Dr, KNOXVILLE, TN 64156","dot":"1620061","ph":"(483) 581-3333","sups":['JOSEPH MARTIN', 'ANA CLARK', 'JOSEPH SMITH']},
    {"name":"ROBINSON FREIGHT SYSTEMS ENTERPRISES LLC","addr":"1709 Terminal Rd, GREENSBORO, NC 31121","dot":"2422565","ph":"(521) 392-7580","sups":['JOSE SANCHEZ', 'JOSEPH CLARK', 'MIGUEL LEE']},
    {"name":"ZENITH APEX LINES HOLDINGS INC","addr":"5536 Enterprise Way, JOPLIN, MO 92245","dot":"2284881","ph":"(217) 843-8777","sups":['MIGUEL MARTIN', 'LINDA WHITE', 'MARY JOHNSON']},
    {"name":"DESERT TRUCKING CORP","addr":"5108 Eastgate Dr, COLUMBUS, OH 31253","dot":"3573058","ph":"(935) 357-9755","sups":['DAVID RODRIGUEZ', 'JOSEPH LOPEZ', 'WILLIAM RODRIGUEZ']},
    {"name":"HERNANDEZ CARRIERS CORP","addr":"6011 Highway Dr, INDIANAPOLIS, IN 35921","dot":"1302093","ph":"(306) 379-7808","sups":['KAREN ANDERSON', 'JOSEPH PEREZ', 'MICHAEL MARTINEZ']},
    {"name":"THOMPSON FREIGHT SYSTEMS ENTERPRISES LLC","addr":"8788 Trucking Ln, TULSA, OK 88096","dot":"250164","ph":"(424) 631-5160","sups":['JESSICA TAYLOR', 'MICHAEL HARRIS', 'KAREN ANDERSON']},
    {"name":"NEXUS FREIGHTWAYS CORP","addr":"4748 Main St, SPRINGFIELD, MO 47361","dot":"1296118","ph":"(965) 458-7774","sups":['PATRICIA JACKSON', 'BARBARA HARRIS', 'MARY ANDERSON']},
    {"name":"MARTINEZ EXPRESS INC","addr":"7239 Logistics Blvd, JOPLIN, MO 99030","dot":"909391","ph":"(464) 385-3515","sups":['WILLIAM JONES', 'LAURA SANCHEZ', 'JAMES PEREZ']},
    {"name":"PATRIOT HAULING CORP","addr":"5965 Northgate Blvd, MEMPHIS, TN 95722","dot":"2096774","ph":"(936) 237-9700","sups":['ANTONIO LOPEZ', 'JAMES MARTIN', 'SOFIA RODRIGUEZ']},
    {"name":"FALCON TRANSPORT HOLDINGS INC","addr":"3406 Northgate Blvd, CHATTANOOGA, TN 28446","dot":"3780055","ph":"(696) 860-8489","sups":['SUSAN HERNANDEZ', 'MICHAEL LEWIS', 'RICHARD DAVIS']},
    {"name":"COVENANT TRANSPORT LLC CO","addr":"4427 Main St, JOPLIN, MO 19623","dot":"1384429","ph":"(550) 573-7984","sups":['DAVID GONZALEZ', 'THOMAS THOMPSON', 'JESSICA PEREZ']},
    {"name":"PATRIOT LOGISTICS LLC LP","addr":"326 Corporate Dr, FRESNO, CA 51734","dot":"2862473","ph":"(256) 636-3188","sups":['JOSE CLARK', 'JENNIFER THOMPSON', 'ELIZABETH ROBINSON']},
    {"name":"ROEHL TRANSPORTATION HOLDINGS INC","addr":"9524 Logistics Blvd, BIRMINGHAM, AL 22410","dot":"2875390","ph":"(860) 704-8982","sups":['WILLIAM JACKSON', 'JESSICA GARCIA', 'BARBARA WILLIAMS']},
    {"name":"PLAINS TRANSPORT SERVICES LLC","addr":"298 Northgate Blvd, DALLAS, TX 12420","dot":"1673431","ph":"(591) 806-7246","sups":['ELIZABETH JONES', 'LUIS HARRIS', 'LINDA JONES']},
    {"name":"SCHNEIDER TRANSPORT LLC CO","addr":"3771 Southpoint Dr, LUBBOCK, TX 29831","dot":"1972925","ph":"(377) 965-1332","sups":['SARAH LEE', 'MICHAEL PEREZ', 'LAURA MILLER']},
    {"name":"EAGLE TRANSPORT LLC GROUP LLC","addr":"4915 Westside Dr, CHICAGO, IL 19467","dot":"2831768","ph":"(304) 252-6647","sups":['JENNIFER TAYLOR', 'JENNIFER MOORE', 'THOMAS THOMAS']},
    {"name":"GARCIA CARRIERS INC LP","addr":"160 Highway Dr, JACKSON, MS 59447","dot":"2973187","ph":"(282) 229-4830","sups":['ANA LOPEZ', 'BARBARA RAMIREZ', 'PATRICIA RAMIREZ']},
    {"name":"HERNANDEZ LINES CO","addr":"948 Broad St, CHICAGO, IL 55497","dot":"981414","ph":"(298) 587-9239","sups":['WILLIAM RODRIGUEZ', 'SOFIA GARCIA', 'JENNIFER GONZALEZ']},
    {"name":"HAWK CARRIERS INC ENTERPRISES LLC","addr":"6347 Eastgate Dr, SPRINGFIELD, MO 12201","dot":"3035602","ph":"(413) 837-2742","sups":['JAMES GONZALEZ', 'ELIZABETH JACKSON', 'DAVID JOHNSON']},
    {"name":"JONES TRANSPORT LLC LP","addr":"4294 Distribution Center Rd, ATLANTA, GA 94648","dot":"659553","ph":"(601) 926-3839","sups":['JOSE TAYLOR', 'SARAH JACKSON', 'LUIS PEREZ']},
    {"name":"LEGACY LOGISTICS LLC ENTERPRISES LLC","addr":"3065 Industrial Way, SPRINGFIELD, MO 44334","dot":"661462","ph":"(868) 663-4049","sups":['CARLOS MILLER', 'LUIS WILSON', 'JENNIFER TAYLOR']},
    {"name":"COVENANT LOGISTICS LLC INC","addr":"7816 Industrial Way, AKRON, OH 85098","dot":"3907639","ph":"(749) 922-3503","sups":['DAVID HARRIS', 'SUSAN LOPEZ', 'CARLOS ANDERSON']},
    {"name":"PLAINS FREIGHT INC","addr":"7454 Terminal Rd, LOUISVILLE, KY 41877","dot":"1945676","ph":"(966) 720-8932","sups":['LINDA ANDERSON', 'ANTONIO PEREZ', 'JOSEPH RODRIGUEZ']},
    {"name":"FALCON KNIGHT TRANSPORT LLC","addr":"5608 Enterprise Way, DES MOINES, IA 77686","dot":"2856567","ph":"(280) 739-9850","sups":['SOFIA MILLER', 'ANTONIO TAYLOR', 'LUIS LOPEZ']},
    {"name":"SCHNEIDER CROSS COUNTRY LINES GROUP LLC","addr":"2302 Enterprise Way, COLUMBIA, SC 36521","dot":"2033297","ph":"(282) 856-1977","sups":['BARBARA LEWIS', 'ANA GARCIA', 'THOMAS MILLER']},
    {"name":"HERITAGE SUMMIT LOGISTICS CO","addr":"2364 Park Ave, KNOXVILLE, TN 85164","dot":"1714548","ph":"(739) 366-3061","sups":['CARLOS MARTINEZ', 'KAREN PEREZ', 'ELIZABETH HARRIS']},
    {"name":"RAMIREZ FREIGHT INC","addr":"4409 Eastgate Dr, MONTGOMERY, AL 38330","dot":"3762363","ph":"(926) 778-3342","sups":['JOSE CLARK', 'LAURA JOHNSON', 'LAURA MOORE']},
    {"name":"MIDWEST FREIGHTWAYS ENTERPRISES LLC","addr":"421 Corporate Dr, DAYTON, OH 18335","dot":"3658871","ph":"(979) 697-1192","sups":['SOFIA THOMPSON', 'JOSE BROWN', 'PATRICIA DAVIS']},
    {"name":"ATLANTIC CARRIERS LP","addr":"932 Park Ave, NASHVILLE, TN 23891","dot":"3268054","ph":"(746) 934-1668","sups":['ANTONIO ROBINSON', 'SUSAN MARTINEZ', 'RICHARD MARTINEZ']},
    {"name":"INTERSTATE EXPRESS GROUP LLC","addr":"9886 Broad St, SHREVEPORT, LA 92645","dot":"2095084","ph":"(661) 749-7250","sups":['ROBERT LEWIS', 'CARLOS HERNANDEZ', 'MIGUEL LEE']},
    {"name":"WESTERN LOGISTICS HOLDINGS INC","addr":"3762 Southpoint Dr, NASHVILLE, TN 87191","dot":"3391133","ph":"(462) 216-8866","sups":['JESSICA RAMIREZ', 'JENNIFER BROWN', 'KAREN WHITE']},
    {"name":"FALCON TRANSPORT LLC CO","addr":"9897 Eastgate Dr, MOBILE, AL 49236","dot":"1294433","ph":"(980) 420-4235","sups":['WILLIAM MARTIN', 'JESSICA ANDERSON', 'KAREN JONES']},
    {"name":"COASTAL TRANSPORT SERVICES LP","addr":"5541 Distribution Center Rd, BIRMINGHAM, AL 74348","dot":"3718390","ph":"(795) 474-7320","sups":['THOMAS MARTINEZ', 'CARLOS JONES', 'THOMAS HERNANDEZ']},
    {"name":"INDEPENDENCE TRANSPORTATION LP","addr":"7666 Northgate Blvd, BATON ROUGE, LA 23807","dot":"2169612","ph":"(750) 711-8562","sups":['JENNIFER JONES', 'JOSE LOPEZ', 'MICHAEL JONES']},
    {"name":"LAKESIDE LIBERTY BELL FREIGHTWAYS GROUP LLC","addr":"4457 Terminal Rd, INDIANAPOLIS, IN 54209","dot":"3748931","ph":"(984) 997-3850","sups":['MARY RAMIREZ', 'KAREN DAVIS', 'DIANA PEREZ']},
    {"name":"ROEHL NATIONAL CARRIERS INC HOLDINGS INC","addr":"1901 Westside Dr, BOISE, ID 39746","dot":"1287365","ph":"(286) 374-1464","sups":['SUSAN SANCHEZ', 'JOSE HARRIS', 'LAURA THOMPSON']},
    {"name":"DAVIS EXPRESS ENTERPRISES LLC","addr":"2594 Highway Dr, JACKSON, MS 92333","dot":"3822232","ph":"(390) 821-6277","sups":['WILLIAM ANDERSON', 'DAVID ANDERSON', 'KAREN JACKSON']},
    {"name":"FALCON AMERICAN LOGISTICS GROUP LLC","addr":"2097 Eastgate Dr, JOPLIN, MO 60614","dot":"3119443","ph":"(841) 606-6382","sups":['JOHN WILLIAMS', 'LUIS PEREZ', 'LINDA JOHNSON']},
    {"name":"CONTINENTAL FREIGHT SYSTEMS GROUP LLC","addr":"1386 Westside Dr, LUBBOCK, TX 56663","dot":"615484","ph":"(532) 549-2329","sups":['RICHARD WHITE', 'JOHN RAMIREZ', 'JOHN LOPEZ']},
    {"name":"SCHNEIDER FREIGHTWAYS GROUP LLC","addr":"7335 Trucking Ln, LOUISVILLE, KY 32175","dot":"1456731","ph":"(625) 580-1000","sups":['MARY MILLER', 'MICHAEL ANDERSON', 'PATRICIA MARTIN']},
    {"name":"FREEDOM LINES LLC","addr":"7377 Fleet St, NASHVILLE, TN 97259","dot":"1089589","ph":"(674) 526-4085","sups":['JOSEPH MARTINEZ', 'DAVID THOMAS', 'DAVID HARRIS']},
    {"name":"ATLANTIC TRANSPORT CO","addr":"5422 Southpoint Dr, TOLEDO, OH 41611","dot":"3546286","ph":"(589) 982-6395","sups":['MIGUEL RAMIREZ', 'LUIS ANDERSON', 'SUSAN SANCHEZ']},
    {"name":"GREEN VALLEY CARRIERS CO","addr":"7938 Freight Way, MONTGOMERY, AL 77962","dot":"1961343","ph":"(599) 668-1526","sups":['SUSAN THOMPSON', 'JOSE MARTINEZ', 'WILLIAM THOMAS']},
    {"name":"CARGO LOGISTICS LLC LLC","addr":"879 Cargo Way, JOPLIN, MO 51599","dot":"945224","ph":"(410) 637-3711","sups":['BARBARA HERNANDEZ', 'MARY PEREZ', 'MIGUEL WILSON']},
    {"name":"JB HUNT CARRIERS INC","addr":"6051 Main St, BOISE, ID 15988","dot":"538923","ph":"(568) 210-6724","sups":['MIGUEL ROBINSON', 'JAMES RODRIGUEZ', 'SUSAN WILLIAMS']},
    {"name":"FREIGHT LOAD STAR EXPRESS LP","addr":"1410 Northgate Blvd, DENVER, CO 53984","dot":"3271676","ph":"(814) 788-1481","sups":['SUSAN LEWIS', 'THOMAS RAMIREZ', 'WILLIAM HERNANDEZ']},
    {"name":"USA TRANSPORTATION CO","addr":"7305 Depot St, EVANSVILLE, IN 82941","dot":"2825009","ph":"(376) 992-8263","sups":['MARIA SMITH', 'WILLIAM WILLIAMS', 'JESSICA HERNANDEZ']},
    {"name":"LEGACY LINES GROUP LLC","addr":"4516 Freight Way, SPRINGFIELD, MO 93071","dot":"1873802","ph":"(736) 264-4331","sups":['CHARLES PEREZ', 'LINDA HARRIS', 'MARY ANDERSON']},
    {"name":"PINNACLE MIDWEST CARRIERS INC GROUP LLC","addr":"4249 Westside Dr, FORT WORTH, TX 83947","dot":"933789","ph":"(580) 682-2690","sups":['JENNIFER MARTINEZ', 'BARBARA THOMAS', 'DIANA JOHNSON']},
    {"name":"XPO CARRIERS INC ENTERPRISES LLC","addr":"489 Cargo Way, SHREVEPORT, LA 82851","dot":"596776","ph":"(226) 776-8070","sups":['MICHAEL THOMPSON', 'JOSEPH THOMAS', 'JOSEPH LEE']},
    {"name":"SOUTHERN TRUCKING INC","addr":"5071 Eastgate Dr, MEMPHIS, TN 96041","dot":"552927","ph":"(350) 488-2497","sups":['JENNIFER LOPEZ', 'JESSICA HARRIS', 'LAURA LEE']},
    {"name":"SANCHEZ FREIGHT SYSTEMS LP","addr":"3473 Southpoint Dr, NASHVILLE, TN 17927","dot":"2520782","ph":"(245) 810-4316","sups":['JOSEPH MARTIN', 'JENNIFER SMITH', 'MARIA CLARK']},
    {"name":"MILLER TRANSPORT LLC CORP","addr":"778 Industrial Way, RENO, NV 16034","dot":"1514933","ph":"(228) 902-6468","sups":['LAURA SANCHEZ', 'DAVID SMITH', 'THOMAS TAYLOR']},
    {"name":"SUMMIT GREEN VALLEY CARRIERS HOLDINGS INC","addr":"3570 Broad St, DENVER, CO 72276","dot":"2486684","ph":"(907) 726-3854","sups":['MARIA ROBINSON', 'THOMAS ROBINSON', 'ANTONIO MILLER']},
    {"name":"HORIZON COVENANT FREIGHT SYSTEMS GROUP LLC","addr":"6049 Main St, SALT LAKE CITY, UT 55170","dot":"3496183","ph":"(615) 476-1284","sups":['JOHN GARCIA', 'JOSEPH HARRIS', 'JESSICA PEREZ']},
    {"name":"RODRIGUEZ FREIGHT LP","addr":"4633 Freight Way, SPOKANE, WA 99122","dot":"1794995","ph":"(366) 560-5174","sups":['JOSEPH CLARK', 'MIGUEL JACKSON', 'LAURA THOMPSON']},
    {"name":"ZENITH MOMENTUM TRANSPORT SERVICES HOLDINGS INC","addr":"4323 Industrial Way, GREENSBORO, NC 30538","dot":"3445357","ph":"(861) 376-5282","sups":['LAURA ANDERSON', 'JOSEPH THOMAS', 'CHARLES SANCHEZ']},
    {"name":"EASTERN LOGISTICS GROUP LLC","addr":"6508 Industrial Pkwy, FRESNO, CA 67233","dot":"725096","ph":"(951) 401-8486","sups":['LINDA TAYLOR', 'BARBARA WILSON', 'JAMES CLARK']},
    {"name":"WHITE TRUCKING ENTERPRISES LLC","addr":"5799 Depot St, DENVER, CO 32279","dot":"2018261","ph":"(515) 624-6640","sups":['SARAH WILSON', 'MIGUEL MARTINEZ', 'JOHN JONES']},
    {"name":"JB HUNT FREIGHT SYSTEMS LLC","addr":"2284 Westside Dr, JACKSON, MS 29984","dot":"851272","ph":"(678) 733-2804","sups":['JOSEPH SANCHEZ', 'SUSAN DAVIS', 'MARIA HERNANDEZ']},
    {"name":"HERNANDEZ TRANSPORT GROUP LLC","addr":"3468 Business Center Dr, HOUSTON, TX 81376","dot":"1607455","ph":"(514) 859-7999","sups":['WILLIAM JOHNSON', 'JOHN GARCIA', 'DAVID WHITE']},
    {"name":"PINNACLE STAR CARRIERS INC CORP","addr":"2063 Industrial Way, COLUMBUS, OH 75138","dot":"2759165","ph":"(339) 256-3910","sups":['SUSAN JACKSON', 'MARY THOMPSON', 'CHARLES MILLER']},
    {"name":"PACIFIC TRUCKING CO CO","addr":"6804 Business Center Dr, HOUSTON, TX 61980","dot":"3049389","ph":"(332) 578-1597","sups":['JESSICA GONZALEZ', 'BARBARA JONES', 'SOFIA THOMAS']},
    {"name":"WESTERN TRANSPORT CO","addr":"4251 Industrial Pkwy, ALBUQUERQUE, NM 72072","dot":"2736038","ph":"(866) 419-6423","sups":['MARIA THOMAS', 'DIANA CLARK', 'JOSE CLARK']},
    {"name":"WILSON CARRIERS INC LP","addr":"1085 Airport Rd, FRESNO, CA 42965","dot":"2373516","ph":"(276) 636-6192","sups":['CARLOS ROBINSON', 'JOSEPH LEWIS', 'BARBARA WHITE']},
    {"name":"WERNER PACIFIC LOGISTICS GROUP LP","addr":"5712 Enterprise Way, KANSAS CITY, MO 12074","dot":"729532","ph":"(841) 211-7639","sups":['SARAH RAMIREZ', 'LUIS JONES', 'ANA JOHNSON']},
    {"name":"RAMIREZ FREIGHTWAYS INC","addr":"1779 Trucking Ln, DES MOINES, IA 49635","dot":"3348034","ph":"(724) 339-6783","sups":['WILLIAM JOHNSON', 'MARIA HERNANDEZ', 'JESSICA WILLIAMS']},
    {"name":"MOORE TRANSPORT SERVICES LLC","addr":"9414 Airport Rd, JOPLIN, MO 60086","dot":"3293009","ph":"(304) 988-8980","sups":['LAURA JONES', 'SUSAN LEE', 'MIGUEL SMITH']},
    {"name":"ROYAL TRANSPORTATION CORP","addr":"3770 Industrial Pkwy, KANSAS CITY, MO 22819","dot":"2168462","ph":"(836) 844-4157","sups":['CHARLES JOHNSON', 'CARLOS DAVIS', 'CHARLES ROBINSON']},
    {"name":"LOAD STAR FREIGHT LOGISTICS LLC","addr":"5233 Depot St, RENO, NV 25335","dot":"2700502","ph":"(870) 537-1249","sups":['ANA THOMAS', 'JOSEPH WHITE', 'THOMAS THOMPSON']},
    {"name":"SMITH FREIGHTWAYS GROUP LLC","addr":"8544 Eastgate Dr, AMARILLO, TX 91378","dot":"2760783","ph":"(211) 489-8461","sups":['ANA ROBINSON', 'JOSE MARTINEZ', 'JESSICA BROWN']},
    {"name":"GARCIA EXPRESS HOLDINGS INC","addr":"8993 Industrial Way, ALBUQUERQUE, NM 63096","dot":"304685","ph":"(820) 875-9079","sups":['MARY LEE', 'DAVID HERNANDEZ', 'BARBARA CLARK']},
    {"name":"APEX LOGISTICS LLC ENTERPRISES LLC","addr":"434 Terminal Rd, MEMPHIS, TN 12895","dot":"899696","ph":"(845) 515-6494","sups":['LINDA SANCHEZ', 'ANTONIO TAYLOR', 'JESSICA MOORE']},
    {"name":"ZENITH TRUCKING LP","addr":"3362 Park Ave, PORTLAND, OR 55420","dot":"730312","ph":"(332) 204-5928","sups":['THOMAS BROWN', 'DAVID CLARK', 'CARLOS CLARK']},
    {"name":"NATIONAL TRANSPORTATION ENTERPRISES LLC","addr":"6662 Terminal Rd, WICHITA, KS 42331","dot":"1769993","ph":"(501) 926-7279","sups":['KAREN LEWIS', 'THOMAS WHITE', 'PATRICIA MARTINEZ']},
    {"name":"TRAIL BLAZER FREIGHTWAYS LP","addr":"4427 Industrial Way, COLUMBUS, OH 69408","dot":"2219343","ph":"(336) 774-1686","sups":['CHARLES MOORE', 'ROBERT THOMAS', 'PATRICIA GARCIA']},
    {"name":"WILLIAMS FREIGHT SYSTEMS HOLDINGS INC","addr":"3818 Corporate Dr, NASHVILLE, TN 93786","dot":"3899580","ph":"(970) 688-5465","sups":['CHARLES WILSON', 'MICHAEL GONZALEZ', 'JOSE LEWIS']},
    {"name":"SWIFT LOGISTICS GROUP LP","addr":"564 Highway Dr, DALLAS, TX 87682","dot":"1103105","ph":"(657) 405-4447","sups":['MARIA MARTIN', 'DIANA CLARK', 'LAURA MARTINEZ']},
    {"name":"RUSH LOGISTICS CORP","addr":"7300 Terminal Rd, HOUSTON, TX 25074","dot":"2761323","ph":"(529) 384-9442","sups":['JENNIFER MOORE', 'ELIZABETH JACKSON', 'CHARLES CLARK']},
    {"name":"EASTERN CARRIERS INC","addr":"898 Enterprise Way, EVANSVILLE, IN 74295","dot":"223273","ph":"(550) 381-7094","sups":['JAMES LEE', 'ROBERT MARTIN', 'JESSICA JACKSON']},
    {"name":"APEX PRIME FREIGHT CO","addr":"2022 Broad St, AKRON, OH 72829","dot":"2790995","ph":"(754) 395-6998","sups":['SUSAN LEWIS', 'LINDA RODRIGUEZ', 'DIANA LEE']},
    {"name":"ROYAL FREIGHT GROUP LLC","addr":"4486 Logistics Blvd, TULSA, OK 16470","dot":"1393405","ph":"(257) 213-2725","sups":['ANTONIO LOPEZ', 'ANTONIO GONZALEZ', 'SARAH LEWIS']},
    {"name":"NORTHERN FREIGHTWAYS INC","addr":"4481 Southpoint Dr, SHREVEPORT, LA 59524","dot":"3107835","ph":"(859) 603-4671","sups":['CHARLES CLARK', 'WILLIAM THOMPSON', 'MICHAEL LEWIS']},
    {"name":"FREEDOM LAKESIDE TRANSPORTATION LP","addr":"988 Broad St, GREENSBORO, NC 98581","dot":"3743342","ph":"(317) 782-9869","sups":['SARAH LOPEZ', 'MIGUEL DAVIS', 'ELIZABETH WILLIAMS']},
    {"name":"HEARTLAND TRUCKING CO GROUP LLC","addr":"1369 Terminal Rd, KNOXVILLE, TN 54762","dot":"2373503","ph":"(816) 687-5331","sups":['MARY WILLIAMS', 'CARLOS WILSON', 'MICHAEL ANDERSON']},
    {"name":"PRIME RUSH TRANSPORT LLC","addr":"1104 Depot St, TULSA, OK 98132","dot":"3666574","ph":"(605) 878-6541","sups":['PATRICIA JOHNSON', 'DIANA HARRIS', 'MARIA MARTIN']},
    {"name":"TAYLOR LOGISTICS GROUP LP","addr":"4819 Enterprise Way, SEATTLE, WA 85086","dot":"2074636","ph":"(814) 773-2153","sups":['CHARLES MARTIN', 'WILLIAM MARTIN', 'MARIA GARCIA']},
    {"name":"VANGUARD USA EXPRESS LLC","addr":"9923 Depot St, GREENSBORO, NC 11102","dot":"3527609","ph":"(978) 507-9248","sups":['SUSAN HERNANDEZ', 'JOSE HARRIS', 'ROBERT JONES']},
    {"name":"PIONEER FREIGHTWAYS CORP","addr":"9264 Westside Dr, SALT LAKE CITY, UT 20054","dot":"3926459","ph":"(318) 655-7844","sups":['MIGUEL SMITH', 'PATRICIA THOMPSON', 'JOHN LEWIS']},
    {"name":"CARGO MASTER SHIPPING CORP","addr":"2069 Distribution Center Rd, SALT LAKE CITY, UT 80651","dot":"2671319","ph":"(648) 772-3770","sups":['JAMES WHITE', 'KAREN GARCIA', 'SARAH SMITH']},
    {"name":"SUMMIT STERLING TRANSPORT HOLDINGS INC","addr":"3756 Industrial Pkwy, PHOENIX, AZ 82713","dot":"1694912","ph":"(790) 231-2642","sups":['RICHARD JONES', 'CARLOS JOHNSON', 'LUIS MARTINEZ']},
    {"name":"ROYAL TRANSPORT SERVICES ENTERPRISES LLC","addr":"7842 Cargo Way, BAKERSFIELD, CA 51182","dot":"1058500","ph":"(345) 648-4360","sups":['CARLOS WILLIAMS', 'ANTONIO WHITE', 'THOMAS MARTINEZ']},
    {"name":"TRANS LOGISTICS GROUP LLC","addr":"4017 Park Ave, SPRINGFIELD, MO 81699","dot":"3942594","ph":"(722) 309-2596","sups":['SARAH SANCHEZ', 'BARBARA DAVIS', 'JENNIFER JOHNSON']},
    {"name":"THOMAS LINES LLC","addr":"5902 Depot St, ATLANTA, GA 82325","dot":"2924981","ph":"(352) 546-8335","sups":['CHARLES RODRIGUEZ', 'RICHARD ROBINSON', 'MICHAEL LEWIS']},
    {"name":"MILLER FREIGHT SYSTEMS LLC","addr":"790 Broad St, ATLANTA, GA 59526","dot":"3960324","ph":"(325) 241-6642","sups":['ANA HARRIS', 'LUIS TAYLOR', 'LUIS CLARK']},
    {"name":"AMERICAN LIBERTY LINES HOLDINGS INC","addr":"4216 Highway Dr, MOBILE, AL 49091","dot":"1744346","ph":"(308) 840-3736","sups":['MARY LOPEZ', 'THOMAS MARTINEZ', 'MIGUEL TAYLOR']},
    {"name":"WHITE TRUCKING CO LP","addr":"2136 Park Ave, LUBBOCK, TX 13081","dot":"3796745","ph":"(487) 393-9253","sups":['ANA JACKSON', 'MICHAEL SMITH', 'JESSICA THOMAS']},
    {"name":"HIGHWAY DIAMOND TRANSPORT HOLDINGS INC","addr":"8701 Northgate Blvd, MEMPHIS, TN 96775","dot":"3299588","ph":"(780) 367-3952","sups":['DAVID GARCIA', 'ROBERT LEWIS', 'CHARLES RODRIGUEZ']},
    {"name":"FALCON LOGISTICS LLC","addr":"3825 Freight Way, DAYTON, OH 42562","dot":"2931146","ph":"(371) 651-2947","sups":['JOSE TAYLOR', 'SARAH JACKSON', 'JOSE THOMPSON']},
    {"name":"DAVIS FREIGHT SYSTEMS ENTERPRISES LLC","addr":"7951 Industrial Way, LAREDO, TX 34042","dot":"163249","ph":"(682) 739-3223","sups":['LINDA HARRIS', 'JOHN WILSON', 'ANA LOPEZ']},
    {"name":"LOAD STAR MOMENTUM TRUCKING CO ENTERPRISES LLC","addr":"4234 Main St, SPRINGFIELD, MO 19553","dot":"226649","ph":"(705) 725-9898","sups":['LAURA ROBINSON', 'SUSAN TAYLOR', 'ELIZABETH THOMPSON']},
    {"name":"BROWN FREIGHT HOLDINGS INC","addr":"3965 Southpoint Dr, KNOXVILLE, TN 65407","dot":"1076398","ph":"(887) 363-5569","sups":['MARIA DAVIS', 'JESSICA LEWIS', 'JOSEPH MOORE']},
    {"name":"JOHNSON EXPRESS INC","addr":"2294 Eastgate Dr, GRAND RAPIDS, MI 56410","dot":"2257356","ph":"(592) 806-5764","sups":['LAURA MILLER', 'MARIA MILLER', 'SOFIA CLARK']},
    {"name":"TRANS FRONTIER EXPRESS LLC","addr":"9364 Highway Dr, AMARILLO, TX 36566","dot":"1630827","ph":"(326) 251-5851","sups":['JOHN RAMIREZ', 'JOHN HERNANDEZ', 'JOSEPH SMITH']},
    {"name":"WESTERN CROSS COUNTRY SHIPPING HOLDINGS INC","addr":"3029 Corporate Dr, EL PASO, TX 53333","dot":"1947025","ph":"(419) 416-8777","sups":['JOSEPH RODRIGUEZ', 'DIANA CLARK', 'MARY CLARK']},
    {"name":"UNITED WESTERN LOGISTICS LLC CO","addr":"8475 Industrial Way, FRESNO, CA 13054","dot":"213555","ph":"(402) 310-9329","sups":['WILLIAM SANCHEZ', 'DIANA BROWN', 'MIGUEL MOORE']},
    {"name":"AMERICAN TRANSPORT LLC CORP","addr":"3130 Main St, CORPUS CHRISTI, TX 90240","dot":"1767357","ph":"(325) 511-7072","sups":['CHARLES JACKSON', 'MICHAEL GARCIA', 'MARIA SANCHEZ']},
    {"name":"CROWN EXPRESS HOLDINGS INC","addr":"8973 Airport Rd, AKRON, OH 11862","dot":"3643282","ph":"(470) 362-4438","sups":['JESSICA SANCHEZ', 'LUIS LEE', 'LINDA CLARK']},
    {"name":"MIDWEST ROAD KING LOGISTICS GROUP INC","addr":"8739 Fleet St, BIRMINGHAM, AL 24440","dot":"346116","ph":"(878) 353-6165","sups":['KAREN RODRIGUEZ', 'SOFIA MILLER', 'MARIA WILLIAMS']},
    {"name":"LIBERTY DIAMOND HAULING GROUP LLC","addr":"3829 Distribution Center Rd, HOUSTON, TX 55008","dot":"2020110","ph":"(747) 327-1401","sups":['SARAH ROBINSON', 'MIGUEL WILLIAMS', 'MARIA SANCHEZ']},
    {"name":"HEARTLAND PREMIER FREIGHT SYSTEMS LP","addr":"5606 Industrial Pkwy, ATLANTA, GA 57990","dot":"1290487","ph":"(339) 706-5175","sups":['BARBARA HARRIS', 'ANTONIO LOPEZ', 'MIGUEL JOHNSON']},
    {"name":"ZENITH LOGISTICS GROUP LLC","addr":"1259 Enterprise Way, TOLEDO, OH 92639","dot":"1341829","ph":"(519) 966-4685","sups":['JAMES JOHNSON', 'CHARLES BROWN', 'CARLOS MILLER']},
    {"name":"DAVIS FREIGHTWAYS INC","addr":"6353 Fleet St, INDIANAPOLIS, IN 64486","dot":"907089","ph":"(885) 760-9398","sups":['ANA JACKSON', 'DAVID WHITE', 'JOHN WILLIAMS']},
    {"name":"CROWN FREIGHTWAYS GROUP LLC","addr":"1407 Northgate Blvd, COLUMBUS, OH 56223","dot":"2313558","ph":"(647) 480-5847","sups":['MICHAEL JONES', 'ROBERT WILSON', 'MIGUEL MARTINEZ']},
    {"name":"JACKSON CARRIERS ENTERPRISES LLC","addr":"5528 Northgate Blvd, FORT WAYNE, IN 49763","dot":"2316124","ph":"(225) 582-7165","sups":['LUIS RAMIREZ', 'SUSAN JACKSON', 'PATRICIA HERNANDEZ']},
    {"name":"RED RIVER SHIPPING LP","addr":"4570 Industrial Pkwy, FORT WORTH, TX 71209","dot":"332577","ph":"(985) 843-5490","sups":['PATRICIA GONZALEZ', 'DAVID MILLER', 'DAVID JOHNSON']},
    {"name":"JONES CARRIERS INC CO","addr":"7309 Business Center Dr, LUBBOCK, TX 34516","dot":"3539702","ph":"(976) 930-8872","sups":['MARY SANCHEZ', 'SARAH THOMAS', 'SOFIA MILLER']},
    {"name":"APEX TRANSPORTATION CORP","addr":"880 Eastgate Dr, CORPUS CHRISTI, TX 74076","dot":"190089","ph":"(756) 213-7720","sups":['THOMAS WHITE', 'LUIS MILLER', 'JENNIFER SMITH']},
    {"name":"LEWIS TRANSPORT GROUP LLC","addr":"2770 Highway Dr, LANSING, MI 69774","dot":"2628606","ph":"(895) 608-5563","sups":['SUSAN LEE', 'MIGUEL SMITH', 'DAVID CLARK']},
    {"name":"CATALYST KNIGHT TRANSPORT LLC CO","addr":"7559 Enterprise Way, BAKERSFIELD, CA 31308","dot":"2301472","ph":"(680) 830-4996","sups":['SUSAN PEREZ', 'RICHARD JACKSON', 'JESSICA CLARK']},
    {"name":"INTERSTATE RUSH SHIPPING CORP","addr":"4317 Business Center Dr, MEMPHIS, TN 22222","dot":"1282038","ph":"(596) 654-7800","sups":['JESSICA WILSON', 'THOMAS THOMAS', 'MARY MOORE']},
    {"name":"ROBINSON LOGISTICS GROUP HOLDINGS INC","addr":"1708 Airport Rd, MONTGOMERY, AL 28612","dot":"3679242","ph":"(418) 738-3146","sups":['MARY WILLIAMS', 'PATRICIA CLARK', 'RICHARD WILSON']},
    {"name":"BIG RIG CARRIERS ENTERPRISES LLC","addr":"4123 Enterprise Way, GREENSBORO, NC 50598","dot":"1691969","ph":"(421) 883-3929","sups":['SARAH SMITH', 'LAURA JONES', 'ANA MARTINEZ']},
    {"name":"JOHNSON HAULING GROUP LLC","addr":"7158 Distribution Center Rd, CORPUS CHRISTI, TX 31133","dot":"422362","ph":"(305) 206-3094","sups":['MARIA GONZALEZ', 'LAURA LEWIS', 'ANTONIO SANCHEZ']},
    {"name":"PLATINUM LOGISTICS LLC GROUP LLC","addr":"1744 Depot St, SHREVEPORT, LA 58390","dot":"3487386","ph":"(914) 554-2243","sups":['MARIA ANDERSON', 'THOMAS JOHNSON', 'CARLOS THOMAS']},
    {"name":"APEX FALCON TRANSPORTATION ENTERPRISES LLC","addr":"9388 Broad St, TULSA, OK 65064","dot":"1722600","ph":"(309) 827-3707","sups":['SOFIA WILLIAMS', 'RICHARD RAMIREZ', 'BARBARA SANCHEZ']},
    {"name":"INDEPENDENCE CONTINENTAL TRUCKING CO LLC","addr":"9628 Fleet St, BOISE, ID 38599","dot":"3397616","ph":"(646) 256-8860","sups":['JOHN HARRIS', 'DIANA SMITH', 'MARIA DAVIS']},
    {"name":"XPO TRANSPORT SERVICES LP","addr":"7161 Main St, NASHVILLE, TN 57368","dot":"1095954","ph":"(474) 938-4856","sups":['KAREN THOMAS', 'DIANA GONZALEZ', 'SUSAN PEREZ']},
    {"name":"TRANS FREIGHT SYSTEMS CO","addr":"2881 Southpoint Dr, MINNEAPOLIS, MN 26005","dot":"2964332","ph":"(821) 609-7176","sups":['ROBERT TAYLOR', 'JOHN SANCHEZ', 'LAURA ROBINSON']},
    {"name":"MILLER TRANSPORT SERVICES CORP","addr":"5864 Business Center Dr, RENO, NV 40919","dot":"2577100","ph":"(793) 932-2255","sups":['RICHARD DAVIS', 'ELIZABETH GARCIA', 'SOFIA LOPEZ']},
    {"name":"WILSON CARRIERS CORP","addr":"3299 Fleet St, BIRMINGHAM, AL 33402","dot":"3858675","ph":"(952) 308-9164","sups":['CHARLES LEE', 'BARBARA ROBINSON', 'MARY LEE']},
    {"name":"EAGLE EXPRESS ENTERPRISES LLC","addr":"236 Cargo Way, DAYTON, OH 33065","dot":"1761472","ph":"(816) 862-1481","sups":['SUSAN THOMPSON', 'ELIZABETH LEE', 'MARY MOORE']},
    {"name":"SOUTHERN TRANSPORT SERVICES INC","addr":"1196 Broad St, MILWAUKEE, WI 70231","dot":"2385711","ph":"(900) 325-3065","sups":['BARBARA SMITH', 'CHARLES MARTIN', 'JAMES RAMIREZ']},
    {"name":"VANGUARD FREIGHT HAULING INC","addr":"655 Distribution Center Rd, SAN ANTONIO, TX 24398","dot":"1435504","ph":"(818) 449-5435","sups":['CARLOS RAMIREZ', 'ROBERT WILLIAMS', 'RICHARD MARTIN']},
    {"name":"HAWK TRANSPORT LP","addr":"2982 Industrial Pkwy, FORT WORTH, TX 77182","dot":"1378490","ph":"(914) 477-6758","sups":['JOSE GONZALEZ', 'PATRICIA MARTINEZ', 'MICHAEL THOMAS']},
    {"name":"ROYAL ROEHL TRUCKING CORP","addr":"7721 Westside Dr, MONTGOMERY, AL 40126","dot":"163269","ph":"(787) 500-9599","sups":['JAMES MOORE', 'LINDA JACKSON', 'LAURA JONES']},
    {"name":"CONTINENTAL FREIGHT TRANSPORT SERVICES GROUP LLC","addr":"7372 Corporate Dr, CHICAGO, IL 91543","dot":"3189615","ph":"(668) 313-6516","sups":['DIANA CLARK', 'JESSICA PEREZ', 'JOSE SANCHEZ']},
    {"name":"RUSH ALL AMERICAN LOGISTICS GROUP CORP","addr":"4345 Terminal Rd, SHREVEPORT, LA 44285","dot":"416614","ph":"(502) 353-8643","sups":['LINDA GARCIA', 'JOSE TAYLOR', 'KAREN HERNANDEZ']},
    {"name":"JACKSON TRANSPORT CORP","addr":"7119 Business Center Dr, AKRON, OH 12357","dot":"2676823","ph":"(534) 308-3537","sups":['LINDA WILSON', 'LUIS WILSON', 'JESSICA LEE']},
    {"name":"EAGLE IRON TRANSPORT SERVICES LP","addr":"9675 Fleet St, OKLAHOMA CITY, OK 63390","dot":"3978379","ph":"(492) 541-5801","sups":['SUSAN GONZALEZ', 'JENNIFER RODRIGUEZ', 'DAVID MILLER']},
    {"name":"MOMENTUM FALCON LOGISTICS LLC CO","addr":"5468 Main St, TOLEDO, OH 97721","dot":"3406481","ph":"(586) 803-6851","sups":['BARBARA GONZALEZ', 'SUSAN JOHNSON', 'MIGUEL CLARK']},
    {"name":"XPO TRANSPORTATION CORP","addr":"9785 Distribution Center Rd, CHICAGO, IL 39015","dot":"2467354","ph":"(382) 368-9915","sups":['SOFIA WILLIAMS', 'LUIS THOMPSON', 'JESSICA DAVIS']},
    {"name":"HEARTLAND DIAMOND FREIGHTWAYS INC","addr":"8696 Northgate Blvd, OMAHA, NE 39931","dot":"1557167","ph":"(855) 965-1458","sups":['JOHN ROBINSON', 'MIGUEL LEE', 'CHARLES WHITE']},
    {"name":"MOMENTUM EXPRESS CO","addr":"2189 Trucking Ln, LUBBOCK, TX 20676","dot":"1978122","ph":"(819) 316-8024","sups":['PATRICIA LEE', 'JENNIFER WILSON', 'WILLIAM RODRIGUEZ']},
    {"name":"PREMIER FREIGHT SYSTEMS LLC","addr":"733 Cargo Way, COLUMBIA, SC 18511","dot":"3859378","ph":"(702) 696-1078","sups":['LINDA HARRIS', 'JENNIFER THOMPSON', 'JESSICA HARRIS']},
    {"name":"PEREZ TRUCKING CO INC","addr":"2139 Corporate Dr, WICHITA, KS 19862","dot":"908070","ph":"(562) 876-8635","sups":['ELIZABETH MARTINEZ', 'SUSAN WILLIAMS', 'JESSICA WILSON']},
    {"name":"ROAD KING APEX FREIGHT SYSTEMS ENTERPRISES LLC","addr":"3421 Business Center Dr, CHATTANOOGA, TN 53917","dot":"2580393","ph":"(586) 971-6067","sups":['ANA LEE', 'LUIS MOORE', 'LAURA HARRIS']},
    {"name":"APEX ESTES LINES HOLDINGS INC","addr":"2206 Commerce Dr, INDIANAPOLIS, IN 46182","dot":"3038976","ph":"(791) 955-7735","sups":['SUSAN SMITH', 'SOFIA CLARK', 'WILLIAM GONZALEZ']},
    {"name":"HORIZON CARRIERS GROUP LLC","addr":"3827 Fleet St, JACKSON, MS 51004","dot":"2672559","ph":"(634) 850-6364","sups":['JAMES RAMIREZ', 'THOMAS ANDERSON', 'LAURA JONES']},
    {"name":"PACIFIC AMERICAN CARRIERS INC CO","addr":"9008 Airport Rd, CHATTANOOGA, TN 76173","dot":"1687622","ph":"(647) 770-4159","sups":['ROBERT JOHNSON', 'SOFIA SMITH', 'JENNIFER BROWN']},
    {"name":"CARGO FREIGHT LLC","addr":"6107 Westside Dr, SPRINGFIELD, MO 84621","dot":"1319577","ph":"(701) 236-7481","sups":['JAMES JACKSON', 'ROBERT MARTIN', 'ELIZABETH THOMAS']},
    {"name":"ALL AMERICAN EXPRESS LP","addr":"6698 Terminal Rd, SHREVEPORT, LA 46886","dot":"1151692","ph":"(640) 504-6576","sups":['MICHAEL GARCIA', 'PATRICIA PEREZ', 'CARLOS MARTIN']},
    {"name":"FRONTIER TRANSPORT LLC CORP","addr":"8381 Eastgate Dr, JOPLIN, MO 39837","dot":"2874665","ph":"(444) 996-7698","sups":['CHARLES RODRIGUEZ', 'ANA ANDERSON', 'BARBARA GONZALEZ']},
    {"name":"ANDERSON FREIGHT SYSTEMS LP","addr":"3366 Distribution Center Rd, LUBBOCK, TX 37500","dot":"1628870","ph":"(692) 632-2618","sups":['THOMAS LEWIS', 'MARY MOORE', 'LUIS MARTIN']},
    {"name":"MIDWEST TRANSPORT LLC LLC","addr":"1970 Eastgate Dr, COLUMBUS, OH 84040","dot":"1515175","ph":"(372) 552-7724","sups":['JENNIFER HARRIS', 'JENNIFER GONZALEZ', 'JENNIFER MARTINEZ']},
    {"name":"CLARK FREIGHTWAYS GROUP LLC","addr":"2305 Industrial Way, BAKERSFIELD, CA 58983","dot":"3270230","ph":"(291) 824-1455","sups":['ANTONIO MILLER', 'JOHN MILLER', 'MARY THOMPSON']},
    {"name":"NORTHERN HAULING LP","addr":"3707 Distribution Center Rd, DENVER, CO 61498","dot":"881292","ph":"(562) 435-9334","sups":['KAREN GONZALEZ', 'LINDA JACKSON', 'MIGUEL MARTINEZ']},
    {"name":"SANCHEZ LOGISTICS HOLDINGS INC","addr":"5161 Business Center Dr, CHATTANOOGA, TN 69968","dot":"2427527","ph":"(784) 841-9750","sups":['ANTONIO CLARK', 'JENNIFER DAVIS', 'SOFIA JACKSON']},
    {"name":"NATIONAL FREEDOM CARRIERS CORP","addr":"4064 Fleet St, LUBBOCK, TX 92921","dot":"3193000","ph":"(776) 484-6122","sups":['JOSE JOHNSON', 'JESSICA LOPEZ', 'RICHARD WILLIAMS']},
    {"name":"COVENANT FREIGHT CO","addr":"9938 Industrial Pkwy, COLUMBIA, SC 62294","dot":"3601986","ph":"(492) 692-6967","sups":['MICHAEL THOMAS', 'SARAH JOHNSON', 'JOSEPH PEREZ']},
    {"name":"APEX LINES LP","addr":"9077 Depot St, FORT WAYNE, IN 43846","dot":"1526606","ph":"(713) 613-2489","sups":['JAMES ANDERSON', 'LAURA CLARK', 'SOFIA JONES']},
    {"name":"LEE FREIGHT LLC","addr":"4579 Logistics Blvd, SAN ANTONIO, TX 50417","dot":"3609107","ph":"(389) 203-9960","sups":['MARY MOORE', 'CHARLES GARCIA', 'ELIZABETH JOHNSON']},
    {"name":"SWIFT APEX TRUCKING GROUP LLC","addr":"6868 Main St, MILWAUKEE, WI 91133","dot":"2236734","ph":"(227) 422-8544","sups":['LUIS ANDERSON', 'JESSICA MILLER', 'SUSAN THOMAS']},
    {"name":"RAMIREZ TRANSPORT SERVICES LLC","addr":"5584 Cargo Way, CHATTANOOGA, TN 93794","dot":"3011426","ph":"(925) 423-5702","sups":['LUIS MOORE', 'MICHAEL HARRIS', 'ANA GARCIA']},
    {"name":"STEEL TRANSPORTATION GROUP LLC","addr":"9241 Broad St, GREENSBORO, NC 67513","dot":"3793519","ph":"(237) 220-4277","sups":['DAVID HARRIS', 'LUIS BROWN', 'LINDA GARCIA']},
    {"name":"DIAMOND FREIGHT INC","addr":"476 Depot St, FORT WAYNE, IN 63484","dot":"163076","ph":"(744) 871-3898","sups":['JAMES RODRIGUEZ', 'ELIZABETH JONES', 'JENNIFER MARTIN']},
    {"name":"ROYAL FREIGHT HOLDINGS INC","addr":"7181 Northgate Blvd, AKRON, OH 52813","dot":"3488703","ph":"(787) 563-8703","sups":['LINDA TAYLOR', 'DIANA CLARK', 'CARLOS WILLIAMS']},
    {"name":"LIBERTY BELL TRANSPORT LLC ENTERPRISES LLC","addr":"6085 Westside Dr, SPOKANE, WA 72259","dot":"524450","ph":"(486) 776-7555","sups":['RICHARD JACKSON', 'KAREN LEWIS', 'JAMES BROWN']},
    {"name":"JOHNSON LOGISTICS LLC LP","addr":"682 Depot St, SALT LAKE CITY, UT 48523","dot":"352626","ph":"(393) 985-6801","sups":['BARBARA HARRIS', 'WILLIAM JOHNSON', 'JAMES HARRIS']},
    {"name":"OLD DOMINION TRUCKING LP","addr":"7497 Fleet St, FRESNO, CA 96005","dot":"2249611","ph":"(597) 490-3779","sups":['SARAH MARTIN', 'DAVID ANDERSON', 'BARBARA TAYLOR']},
    {"name":"GARCIA FREIGHT LLC","addr":"1411 Freight Way, SPOKANE, WA 98386","dot":"1108499","ph":"(724) 661-4101","sups":['ELIZABETH THOMPSON', 'SUSAN ROBINSON', 'JOSE CLARK']},
    {"name":"ROBINSON LINES CORP","addr":"2913 Corporate Dr, FORT WAYNE, IN 42186","dot":"1521627","ph":"(422) 694-4345","sups":['SOFIA THOMAS', 'ELIZABETH LOPEZ', 'LINDA ANDERSON']},
    {"name":"NEXUS FREIGHT INC","addr":"718 Business Center Dr, DALLAS, TX 17764","dot":"3850898","ph":"(594) 636-4494","sups":['PATRICIA ANDERSON', 'JENNIFER JOHNSON', 'JOHN BROWN']},
    {"name":"DIAMOND TRANSPORT SERVICES INC","addr":"2775 Business Center Dr, SAN ANTONIO, TX 67859","dot":"474041","ph":"(497) 572-5095","sups":['JESSICA THOMAS', 'KAREN GARCIA', 'LUIS JONES']},
    {"name":"HAWK LOGISTICS HOLDINGS INC","addr":"4151 Industrial Way, EL PASO, TX 48023","dot":"1257758","ph":"(271) 798-9160","sups":['JOSE MOORE', 'JENNIFER GONZALEZ', 'JESSICA WHITE']},
    {"name":"TITAN PACIFIC LOGISTICS GROUP LLC","addr":"9127 Commerce Dr, SPOKANE, WA 98300","dot":"1424166","ph":"(310) 833-1137","sups":['ROBERT WILLIAMS', 'ANTONIO RAMIREZ', 'RICHARD MARTIN']},
    {"name":"TAYLOR FREIGHT HOLDINGS INC","addr":"7987 Westside Dr, AUSTIN, TX 13074","dot":"3617418","ph":"(812) 532-7619","sups":['ROBERT THOMAS', 'LINDA RODRIGUEZ', 'LUIS GONZALEZ']},
    {"name":"MIDWEST USA FREIGHTWAYS LP","addr":"126 Park Ave, MINNEAPOLIS, MN 99622","dot":"3038544","ph":"(847) 317-1105","sups":['BARBARA JACKSON', 'ANTONIO LOPEZ', 'JAMES SANCHEZ']},
    {"name":"EASTERN LOGISTICS LLC INC","addr":"646 Main St, SEATTLE, WA 18869","dot":"3793855","ph":"(794) 668-8567","sups":['SARAH RODRIGUEZ', 'JOHN WILLIAMS', 'LINDA PEREZ']},
    {"name":"RED RIVER FREIGHT TRUCKING CO LLC","addr":"5730 Industrial Pkwy, SPRINGFIELD, MO 98289","dot":"436522","ph":"(388) 891-5446","sups":['JESSICA GARCIA', 'JOSE THOMPSON', 'SOFIA THOMPSON']},
    {"name":"STAR WERNER TRANSPORT LLC CO","addr":"6180 Commerce Dr, DAYTON, OH 40616","dot":"2019314","ph":"(749) 553-1830","sups":['JESSICA GONZALEZ', 'DAVID THOMAS', 'JOHN HARRIS']},
    {"name":"COASTAL EXPRESS CO","addr":"4222 Southpoint Dr, OMAHA, NE 80890","dot":"2444185","ph":"(325) 800-4732","sups":['CHARLES LEE', 'LINDA ANDERSON', 'CHARLES MILLER']},
    {"name":"USA LOGISTICS LLC","addr":"3390 Fleet St, DENVER, CO 70027","dot":"1256074","ph":"(461) 806-7071","sups":['KAREN JOHNSON', 'LAURA ANDERSON', 'BARBARA DAVIS']},
    {"name":"COVENANT LINES INC","addr":"5736 Industrial Pkwy, KANSAS CITY, MO 62192","dot":"3784389","ph":"(754) 823-4182","sups":['JAMES ANDERSON', 'MARY WILSON', 'ROBERT PEREZ']},
    {"name":"HAWK DIAMOND TRANSPORT LLC LLC","addr":"7332 Westside Dr, RENO, NV 82068","dot":"928697","ph":"(723) 993-9096","sups":['JAMES RAMIREZ', 'JOSE THOMPSON', 'LINDA DAVIS']},
    {"name":"GREEN VALLEY PACIFIC CARRIERS HOLDINGS INC","addr":"1833 Enterprise Way, SPOKANE, WA 67696","dot":"2041353","ph":"(294) 721-4912","sups":['MARIA CLARK', 'WILLIAM TAYLOR', 'ANA TAYLOR']},
    {"name":"HERITAGE TRANSPORT HOLDINGS INC","addr":"8798 Business Center Dr, BAKERSFIELD, CA 17930","dot":"3372344","ph":"(504) 257-8670","sups":['THOMAS RODRIGUEZ', 'THOMAS SMITH', 'CARLOS HERNANDEZ']},
    {"name":"JACKSON HAULING HOLDINGS INC","addr":"4479 Eastgate Dr, BOISE, ID 20569","dot":"810555","ph":"(471) 478-8454","sups":['JAMES MILLER', 'MIGUEL THOMPSON', 'JENNIFER ANDERSON']},
    {"name":"ANDERSON TRUCKING LLC","addr":"4795 Distribution Center Rd, RENO, NV 85294","dot":"1589021","ph":"(422) 495-7741","sups":['PATRICIA RAMIREZ', 'JAMES MOORE', 'ROBERT JACKSON']},
    {"name":"MARTEN APEX TRUCKING CO LLC","addr":"9232 Park Ave, AKRON, OH 41828","dot":"2457740","ph":"(289) 582-4790","sups":['MIGUEL LOPEZ', 'MARIA MARTIN', 'ELIZABETH DAVIS']},
    {"name":"GOLD FREIGHT SYSTEMS LLC","addr":"2791 Airport Rd, TOLEDO, OH 41850","dot":"1387163","ph":"(717) 622-6483","sups":['JOSE LEWIS', 'JOHN JOHNSON', 'LAURA MILLER']},
    {"name":"GARCIA SHIPPING CORP","addr":"2452 Freight Way, INDIANAPOLIS, IN 59338","dot":"3142287","ph":"(711) 856-5217","sups":['ROBERT RODRIGUEZ', 'ANA ANDERSON', 'BARBARA WHITE']},
    {"name":"HEARTLAND TRUCKING CO INC","addr":"3809 Southpoint Dr, MOBILE, AL 97783","dot":"1645383","ph":"(547) 918-6161","sups":['ROBERT LEE', 'JOSEPH WILSON', 'SOFIA HARRIS']},
    {"name":"GREEN VALLEY EXPRESS ENTERPRISES LLC","addr":"8349 Industrial Way, CORPUS CHRISTI, TX 90586","dot":"526066","ph":"(939) 265-5430","sups":['ELIZABETH LEWIS', 'JOHN BROWN', 'JOSE PEREZ']},
    {"name":"MOMENTUM LOGISTICS GROUP CO","addr":"5797 Broad St, FRESNO, CA 42712","dot":"3818390","ph":"(862) 550-9128","sups":['MARY DAVIS', 'ROBERT LOPEZ', 'LINDA JACKSON']},
    {"name":"HARRIS TRANSPORTATION CORP","addr":"485 Terminal Rd, CHARLOTTE, NC 80324","dot":"1204218","ph":"(644) 982-9462","sups":['JAMES HARRIS', 'LAURA HERNANDEZ', 'JENNIFER WILSON']},
    {"name":"PLAINS FREIGHT SYSTEMS LLC","addr":"4982 Highway Dr, EVANSVILLE, IN 56564","dot":"2715275","ph":"(624) 305-7921","sups":['JENNIFER GONZALEZ', 'LUIS JACKSON', 'MARIA MILLER']},
    {"name":"SYNERGY EXPRESS GROUP LLC","addr":"1231 Industrial Way, DALLAS, TX 33907","dot":"2582021","ph":"(391) 748-4471","sups":['DIANA PEREZ', 'CHARLES DAVIS', 'JENNIFER MARTINEZ']},
    {"name":"COASTAL HAULING GROUP LLC","addr":"9042 Trucking Ln, MINNEAPOLIS, MN 13483","dot":"2856705","ph":"(295) 818-5613","sups":['JAMES WHITE', 'CHARLES MILLER', 'THOMAS WILLIAMS']},
    {"name":"RODRIGUEZ CARRIERS LP","addr":"4533 Industrial Way, AUSTIN, TX 19594","dot":"2412066","ph":"(209) 241-6519","sups":['ANTONIO GARCIA', 'RICHARD HERNANDEZ', 'WILLIAM MOORE']},
    {"name":"BIG RIG TRUCKING CO CO","addr":"5871 Depot St, MEMPHIS, TN 43391","dot":"1262197","ph":"(671) 952-7200","sups":['KAREN THOMPSON', 'ANA WILLIAMS', 'LUIS SMITH']},
    {"name":"STERLING TRANSPORT LLC LLC","addr":"4970 Eastgate Dr, KANSAS CITY, MO 36610","dot":"3798341","ph":"(459) 230-1185","sups":['LAURA JONES', 'BARBARA LEE', 'ANTONIO WHITE']},
    {"name":"LOAD STAR HAULING CORP","addr":"4171 Highway Dr, JACKSON, MS 10705","dot":"2885350","ph":"(635) 295-7183","sups":['MARIA HARRIS', 'MICHAEL MARTIN', 'MARY ROBINSON']},
    {"name":"COASTAL SHIPPING GROUP LLC","addr":"2010 Eastgate Dr, RENO, NV 23178","dot":"2522787","ph":"(210) 711-5698","sups":['THOMAS MOORE', 'SARAH JACKSON', 'JOSEPH JOHNSON']},
    {"name":"HEARTLAND LINES LP","addr":"7704 Industrial Way, SEATTLE, WA 81074","dot":"3401761","ph":"(749) 588-9934","sups":['CHARLES LEWIS', 'MARY GARCIA', 'JENNIFER MILLER']},
    {"name":"JOHNSON CARRIERS LP","addr":"7712 Northgate Blvd, BIRMINGHAM, AL 91028","dot":"1635614","ph":"(414) 941-3305","sups":['PATRICIA LEWIS', 'CHARLES RAMIREZ', 'KAREN MARTINEZ']},
    {"name":"HEARTLAND NATIONAL CARRIERS INC LLC","addr":"3482 Highway Dr, DALLAS, TX 32327","dot":"345122","ph":"(648) 905-5222","sups":['WILLIAM MOORE', 'ROBERT LOPEZ', 'JENNIFER RAMIREZ']},
    {"name":"VANGUARD TRANSPORT SERVICES INC","addr":"2010 Fleet St, LUBBOCK, TX 55142","dot":"2983010","ph":"(970) 260-7044","sups":['JAMES MARTINEZ', 'MARY JOHNSON', 'SUSAN ANDERSON']},
    {"name":"VELOCITY MOUNTAIN TRANSPORTATION ENTERPRISES LLC","addr":"6034 Park Ave, DAYTON, OH 90556","dot":"1666985","ph":"(902) 756-4988","sups":['LAURA LEE', 'MARY MARTINEZ', 'JENNIFER RAMIREZ']},
    {"name":"WERNER JB HUNT SHIPPING GROUP LLC","addr":"6693 Southpoint Dr, SPRINGFIELD, MO 14067","dot":"1890186","ph":"(830) 814-3945","sups":['LUIS PEREZ', 'ANA HERNANDEZ', 'MARY MILLER']},
    {"name":"RED RIVER PATRIOT LINES GROUP LLC","addr":"2592 Depot St, KNOXVILLE, TN 45689","dot":"1284451","ph":"(670) 436-6841","sups":['ROBERT CLARK', 'WILLIAM LEWIS', 'ANA WILLIAMS']},
    {"name":"GOLD TRANSPORT SERVICES CORP","addr":"8220 Distribution Center Rd, RICHMOND, VA 24924","dot":"1130358","ph":"(692) 479-5042","sups":['KAREN SMITH', 'ANA WHITE', 'JOSEPH MARTIN']},
    {"name":"CROWN CARRIERS INC INC","addr":"9458 Terminal Rd, MILWAUKEE, WI 92047","dot":"957956","ph":"(921) 448-3090","sups":['JOSE JACKSON', 'WILLIAM SMITH', 'CHARLES ANDERSON']},
    {"name":"SCHNEIDER TITAN FREIGHT LLC","addr":"492 Broad St, AUSTIN, TX 28848","dot":"3275581","ph":"(713) 267-9287","sups":['ROBERT RODRIGUEZ', 'DAVID LEE', 'MARIA GARCIA']},
    {"name":"SMITH CARRIERS INC CORP","addr":"1957 Eastgate Dr, LOUISVILLE, KY 30443","dot":"3601873","ph":"(685) 439-8828","sups":['CARLOS MARTIN', 'ANTONIO WHITE', 'ELIZABETH MARTINEZ']},
    {"name":"LEGACY EASTERN LINES CO","addr":"3288 Cargo Way, LAS VEGAS, NV 62689","dot":"1347420","ph":"(350) 718-4727","sups":['KAREN GONZALEZ', 'JOSEPH JOHNSON', 'JENNIFER DAVIS']},
    {"name":"LAKESIDE LOGISTICS ENTERPRISES LLC","addr":"9468 Westside Dr, PORTLAND, OR 12921","dot":"2830714","ph":"(930) 994-5505","sups":['LUIS THOMAS', 'SUSAN BROWN', 'WILLIAM ROBINSON']},
    {"name":"HERNANDEZ TRANSPORT LLC HOLDINGS INC","addr":"6223 Park Ave, CHARLOTTE, NC 69819","dot":"1386289","ph":"(862) 660-3251","sups":['KAREN LEWIS', 'JENNIFER LEWIS', 'ANTONIO JOHNSON']},
    {"name":"EASTERN CARRIERS CO","addr":"8153 Broad St, CHARLOTTE, NC 72385","dot":"2487360","ph":"(398) 824-3027","sups":['MARIA WHITE', 'THOMAS JOHNSON', 'ELIZABETH BROWN']},
    {"name":"STAR EXPRESS CO","addr":"2135 Trucking Ln, GRAND RAPIDS, MI 77468","dot":"3177790","ph":"(886) 494-6930","sups":['RICHARD MARTINEZ', 'SUSAN MARTIN', 'WILLIAM JONES']},
    {"name":"SYNERGY EXPRESS HOLDINGS INC","addr":"3010 Commerce Dr, ALBUQUERQUE, NM 20755","dot":"2674013","ph":"(238) 407-4046","sups":['LUIS JACKSON', 'THOMAS LEE', 'JESSICA MARTIN']},
    {"name":"STAR TRANSPORT SERVICES INC","addr":"8127 Terminal Rd, DES MOINES, IA 53356","dot":"3751326","ph":"(921) 904-4673","sups":['CARLOS JOHNSON', 'MIGUEL HERNANDEZ', 'CARLOS ANDERSON']},
    {"name":"EXPRESS LOGISTICS LLC HOLDINGS INC","addr":"4336 Logistics Blvd, OMAHA, NE 44031","dot":"3223641","ph":"(481) 770-4566","sups":['LUIS THOMAS', 'JENNIFER RAMIREZ', 'JAMES ANDERSON']},
    {"name":"EXPRESS ROYAL LINES CORP","addr":"1660 Logistics Blvd, CHATTANOOGA, TN 13574","dot":"3822638","ph":"(920) 585-8435","sups":['SUSAN MARTIN', 'MARIA ANDERSON', 'LINDA MILLER']},
    {"name":"COAST TO COAST CARRIERS ENTERPRISES LLC","addr":"6515 Eastgate Dr, SPOKANE, WA 92521","dot":"3985542","ph":"(231) 587-6110","sups":['JAMES TAYLOR', 'SOFIA LEE', 'ANA CLARK']},
    {"name":"INTERSTATE LOGISTICS CORP","addr":"6728 Enterprise Way, MINNEAPOLIS, MN 69100","dot":"3578786","ph":"(848) 307-1738","sups":['CARLOS DAVIS', 'PATRICIA SMITH', 'ANA JONES']},
    {"name":"MOMENTUM EXPRESS TRANSPORT SERVICES HOLDINGS INC","addr":"4632 Airport Rd, AMARILLO, TX 60350","dot":"933215","ph":"(406) 475-4806","sups":['JOHN JONES', 'PATRICIA MARTIN', 'LUIS JONES']},
    {"name":"LAKESIDE IRON LOGISTICS CO","addr":"9026 Northgate Blvd, BATON ROUGE, LA 42943","dot":"1110813","ph":"(524) 636-6116","sups":['JAMES DAVIS', 'JENNIFER WILSON', 'CHARLES THOMPSON']},
    {"name":"HEARTLAND CARRIERS INC LP","addr":"3174 Logistics Blvd, DES MOINES, IA 89220","dot":"1470538","ph":"(533) 699-8910","sups":['LINDA RODRIGUEZ', 'SUSAN WHITE', 'JENNIFER WILSON']},
    {"name":"UNITED TRUCKING HOLDINGS INC","addr":"5600 Westside Dr, MILWAUKEE, WI 95574","dot":"1807187","ph":"(532) 822-8461","sups":['JOSEPH ROBINSON', 'DIANA BROWN', 'LAURA JOHNSON']},
    {"name":"FOUNDERS LOGISTICS CORP","addr":"6643 Freight Way, LAS VEGAS, NV 86891","dot":"259764","ph":"(513) 813-5126","sups":['LINDA LEWIS', 'MARIA JONES', 'DAVID ANDERSON']},
    {"name":"HEARTLAND CARRIERS INC CORP","addr":"8546 Depot St, SEATTLE, WA 14370","dot":"1229963","ph":"(669) 981-1256","sups":['JOSE SMITH', 'BARBARA BROWN', 'SOFIA LEE']},
    {"name":"PEREZ TRANSPORT SERVICES INC","addr":"3084 Distribution Center Rd, LOUISVILLE, KY 57846","dot":"3232735","ph":"(507) 385-7169","sups":['WILLIAM THOMPSON', 'JOSEPH SANCHEZ', 'WILLIAM MARTIN']},
    {"name":"HAWK TRAIL BLAZER SHIPPING CO","addr":"8084 Business Center Dr, MONTGOMERY, AL 88771","dot":"152581","ph":"(545) 582-8575","sups":['JESSICA GONZALEZ', 'JOSEPH WILSON', 'MARY JOHNSON']},
    {"name":"COVENANT FREEDOM LOGISTICS LLC CORP","addr":"5307 Depot St, MINNEAPOLIS, MN 48384","dot":"1379364","ph":"(487) 562-5726","sups":['SOFIA DAVIS', 'PATRICIA MARTIN', 'SUSAN SANCHEZ']},
    {"name":"PRIME CARRIERS INC ENTERPRISES LLC","addr":"7952 Main St, KANSAS CITY, MO 31472","dot":"3890058","ph":"(934) 628-9350","sups":['JOSEPH CLARK', 'CHARLES LEWIS', 'ANTONIO PEREZ']},
    {"name":"MOORE EXPRESS GROUP LLC","addr":"9392 Industrial Pkwy, PHOENIX, AZ 62533","dot":"317460","ph":"(202) 512-6118","sups":['SARAH GARCIA', 'ANTONIO RODRIGUEZ', 'JAMES WILSON']},
    {"name":"PATRIOT ALL AMERICAN TRANSPORT LLC CORP","addr":"2330 Business Center Dr, KANSAS CITY, MO 88088","dot":"1168421","ph":"(277) 636-5865","sups":['JAMES WHITE', 'JOSE LEE', 'JOSE THOMAS']},
    {"name":"STERLING LOGISTICS ENTERPRISES LLC","addr":"5531 Depot St, DENVER, CO 84972","dot":"2954664","ph":"(367) 612-9051","sups":['ANTONIO MARTIN', 'ANTONIO JONES', 'LINDA LEE']},
    {"name":"MIDWEST TITAN TRANSPORT SERVICES GROUP LLC","addr":"5285 Enterprise Way, LAS VEGAS, NV 96283","dot":"1649748","ph":"(251) 968-6953","sups":['DAVID RODRIGUEZ', 'MICHAEL SANCHEZ', 'JOSE MARTINEZ']},
    {"name":"TRAIL BLAZER LOGISTICS LLC LP","addr":"8119 Fleet St, LOUISVILLE, KY 23000","dot":"1116485","ph":"(732) 870-2880","sups":['ELIZABETH RODRIGUEZ', 'BARBARA HARRIS', 'ROBERT PEREZ']},
    {"name":"GREEN VALLEY GOLD LOGISTICS GROUP LLC","addr":"4992 Southpoint Dr, LAS VEGAS, NV 66971","dot":"3512433","ph":"(957) 763-8486","sups":['JOHN LEE', 'JOSE DAVIS', 'PATRICIA WILLIAMS']},
    {"name":"ALL AMERICAN TRUCKING CO GROUP LLC","addr":"5457 Westside Dr, DES MOINES, IA 14733","dot":"1998756","ph":"(250) 269-9765","sups":['MARIA LEE', 'CHARLES MILLER', 'SOFIA RAMIREZ']},
    {"name":"WESTERN ZENITH TRANSPORT LP","addr":"614 Trucking Ln, AKRON, OH 38985","dot":"2836305","ph":"(562) 797-8965","sups":['SARAH BROWN', 'ANTONIO RODRIGUEZ', 'SUSAN WILLIAMS']},
    {"name":"ALL AMERICAN LOGISTICS LLC CORP","addr":"5641 Business Center Dr, PHOENIX, AZ 96422","dot":"2233826","ph":"(422) 984-8485","sups":['JOSEPH JOHNSON', 'MARY MOORE', 'DAVID MARTINEZ']},
    {"name":"ZENITH FREIGHT LOGISTICS LLC CO","addr":"7565 Business Center Dr, DES MOINES, IA 59333","dot":"832214","ph":"(425) 351-2971","sups":['JESSICA JONES', 'ANA JONES', 'ROBERT THOMAS']},
    {"name":"PREMIER HIGHWAY TRANSPORT CO","addr":"2159 Park Ave, AMARILLO, TX 62062","dot":"2990488","ph":"(615) 415-1333","sups":['PATRICIA TAYLOR', 'DAVID GONZALEZ', 'SARAH MOORE']},
    {"name":"NATIONAL FREIGHTWAYS INC","addr":"6246 Broad St, FRESNO, CA 55140","dot":"952426","ph":"(730) 488-4692","sups":['CARLOS RAMIREZ', 'ANA THOMPSON', 'KAREN MOORE']},
    {"name":"VANGUARD TRANSPORT ENTERPRISES LLC","addr":"9590 Industrial Way, EL PASO, TX 45280","dot":"3870828","ph":"(652) 780-5857","sups":['LINDA HERNANDEZ', 'THOMAS ANDERSON', 'BARBARA TAYLOR']},
    {"name":"COVENANT CARRIERS INC CORP","addr":"4056 Industrial Pkwy, AMARILLO, TX 42013","dot":"3047630","ph":"(224) 739-7960","sups":['WILLIAM MARTIN', 'JOSEPH JONES', 'ANTONIO THOMAS']},
    {"name":"SYNERGY SUMMIT SHIPPING LP","addr":"8660 Broad St, TULSA, OK 40893","dot":"2450622","ph":"(763) 810-7816","sups":['PATRICIA GARCIA', 'MARY MOORE', 'DIANA LOPEZ']},
    {"name":"PLATINUM CARGO MASTER LOGISTICS GROUP HOLDINGS INC","addr":"1986 Trucking Ln, FRESNO, CA 81577","dot":"1559138","ph":"(960) 762-4779","sups":['CHARLES JOHNSON', 'LAURA THOMPSON', 'THOMAS CLARK']},
    {"name":"UNITED FOUNDERS FREIGHT SYSTEMS ENTERPRISES LLC","addr":"5605 Industrial Way, CHATTANOOGA, TN 10428","dot":"1835412","ph":"(509) 695-1442","sups":['JOSEPH THOMAS', 'ROBERT WHITE', 'LAURA CLARK']},
    {"name":"FREIGHT LOGISTICS LLC LLC","addr":"6931 Logistics Blvd, AKRON, OH 81330","dot":"1380257","ph":"(718) 303-2059","sups":['DIANA LOPEZ', 'JAMES DAVIS', 'THOMAS DAVIS']},
    {"name":"FREIGHT HAULING LP","addr":"9456 Enterprise Way, DAYTON, OH 18146","dot":"466398","ph":"(552) 467-1661","sups":['RICHARD SMITH', 'LUIS GARCIA', 'KAREN GONZALEZ']},
    {"name":"LEE FREIGHTWAYS GROUP LLC","addr":"1389 Southpoint Dr, AUSTIN, TX 17658","dot":"3797485","ph":"(513) 373-5959","sups":['CARLOS LOPEZ', 'JOSEPH LEE', 'DIANA WILLIAMS']},
    {"name":"ROAD KING TRANSPORT LLC INC","addr":"1589 Commerce Dr, MONTGOMERY, AL 68800","dot":"1653569","ph":"(629) 912-9200","sups":['WILLIAM PEREZ', 'JESSICA JACKSON', 'JOSEPH WILLIAMS']},
    {"name":"FALCON MOUNTAIN EXPRESS INC","addr":"4260 Northgate Blvd, SALT LAKE CITY, UT 73158","dot":"3176620","ph":"(623) 779-5209","sups":['KAREN GONZALEZ', 'JAMES MOORE', 'THOMAS PEREZ']},
    {"name":"CONTINENTAL TRANSPORT LLC ENTERPRISES LLC","addr":"3667 Industrial Pkwy, AMARILLO, TX 26908","dot":"1207260","ph":"(770) 926-7594","sups":['SOFIA GONZALEZ', 'LUIS CLARK', 'DIANA JACKSON']},
    {"name":"TRAIL BLAZER HEARTLAND FREIGHTWAYS CO","addr":"9434 Cargo Way, COLUMBUS, OH 30056","dot":"2751978","ph":"(611) 681-1151","sups":['DIANA HERNANDEZ', 'THOMAS JONES', 'CARLOS HERNANDEZ']},
    {"name":"HAWK CARRIERS INC CORP","addr":"1650 Industrial Pkwy, SPRINGFIELD, MO 36536","dot":"2901612","ph":"(867) 748-8239","sups":['LAURA THOMPSON', 'CHARLES MARTIN', 'THOMAS LEE']},
    {"name":"RODRIGUEZ FREIGHTWAYS CO","addr":"3808 Corporate Dr, LOUISVILLE, KY 84124","dot":"2398427","ph":"(911) 403-3952","sups":['ANTONIO MARTIN', 'LAURA ANDERSON', 'KAREN WILSON']},
    {"name":"MOMENTUM CARRIERS CORP","addr":"4938 Eastgate Dr, KNOXVILLE, TN 86003","dot":"3115459","ph":"(744) 660-2834","sups":['PATRICIA DAVIS', 'CHARLES JACKSON', 'ANTONIO CLARK']},
    {"name":"INTERSTATE LAKESIDE FREIGHTWAYS HOLDINGS INC","addr":"6561 Corporate Dr, CHATTANOOGA, TN 76829","dot":"3664698","ph":"(359) 655-7734","sups":['MARIA LEE', 'MICHAEL LEWIS', 'JAMES MARTINEZ']},
    {"name":"EXPRESS CARRIERS INC CO","addr":"3326 Main St, LANSING, MI 27771","dot":"1751686","ph":"(404) 485-5510","sups":['JOSE MARTINEZ', 'MIGUEL MARTIN', 'MARIA MARTINEZ']},
    {"name":"TRANS FREIGHT INC","addr":"1124 Fleet St, CHARLOTTE, NC 42498","dot":"3953756","ph":"(675) 450-5179","sups":['MIGUEL WHITE', 'MARIA LOPEZ', 'SARAH JACKSON']},
    {"name":"JOHNSON LOGISTICS GROUP LP","addr":"7233 Logistics Blvd, CHICAGO, IL 83673","dot":"1957890","ph":"(316) 998-3897","sups":['ROBERT RAMIREZ', 'ANTONIO MOORE', 'ROBERT GONZALEZ']},
    {"name":"SCHNEIDER NATIONAL FREIGHTWAYS CORP","addr":"9336 Southpoint Dr, JOPLIN, MO 54511","dot":"1841805","ph":"(385) 712-9157","sups":['JOSE JACKSON', 'JESSICA MARTIN', 'MARY JOHNSON']},
    {"name":"LIBERTY TRUCKING LP","addr":"1590 Eastgate Dr, DENVER, CO 13745","dot":"2853213","ph":"(976) 217-1325","sups":['LINDA MOORE', 'JOSE WHITE', 'JESSICA WILSON']},
    {"name":"TRANS TRANSPORT LLC HOLDINGS INC","addr":"8508 Terminal Rd, PHOENIX, AZ 90186","dot":"114166","ph":"(739) 631-4414","sups":['LUIS ROBINSON', 'ROBERT WILSON', 'PATRICIA JACKSON']},
    {"name":"FREEDOM FREIGHT LLC","addr":"284 Terminal Rd, DENVER, CO 21242","dot":"2506441","ph":"(842) 615-5684","sups":['LINDA WILSON', 'LINDA MARTINEZ', 'MIGUEL BROWN']},
    {"name":"WILLIAMS SHIPPING LP","addr":"3865 Cargo Way, LAREDO, TX 57448","dot":"658329","ph":"(420) 812-9692","sups":['PATRICIA SMITH', 'CHARLES WILLIAMS', 'THOMAS LEE']},
    {"name":"GREEN VALLEY FREIGHTWAYS GROUP LLC","addr":"9683 Enterprise Way, BIRMINGHAM, AL 67231","dot":"2444808","ph":"(892) 959-9914","sups":['JESSICA JACKSON', 'JESSICA RAMIREZ', 'ANTONIO LOPEZ']},
    {"name":"GARCIA TRUCKING CO GROUP LLC","addr":"3611 Fleet St, DES MOINES, IA 13872","dot":"2981932","ph":"(713) 826-5915","sups":['KAREN BROWN', 'LUIS LEE', 'CHARLES DAVIS']},
    {"name":"MOUNTAIN TRANSPORTATION CORP","addr":"3799 Westside Dr, MOBILE, AL 11528","dot":"1262010","ph":"(399) 640-3413","sups":['DAVID THOMAS', 'JESSICA WILLIAMS', 'THOMAS ROBINSON']},
    {"name":"DIAMOND HORIZON TRANSPORT SERVICES CO","addr":"1054 Fleet St, KNOXVILLE, TN 25456","dot":"2930706","ph":"(530) 546-2762","sups":['WILLIAM GONZALEZ', 'DIANA JOHNSON', 'SARAH GONZALEZ']},
    {"name":"NORTHERN CARRIERS INC CO","addr":"9102 Eastgate Dr, SAN ANTONIO, TX 13834","dot":"3976468","ph":"(276) 371-5332","sups":['SARAH LOPEZ', 'PATRICIA PEREZ', 'LAURA MILLER']},
    {"name":"LEGACY TRANSPORT LLC CO","addr":"6782 Industrial Way, OKLAHOMA CITY, OK 88853","dot":"1262880","ph":"(823) 677-6940","sups":['JOSE WILLIAMS', 'JOSE WHITE', 'MARY SMITH']},
    {"name":"VANGUARD TRANSPORT LLC HOLDINGS INC","addr":"1804 Park Ave, SALT LAKE CITY, UT 35823","dot":"1362927","ph":"(715) 246-3248","sups":['JESSICA DAVIS', 'CHARLES ROBINSON', 'JENNIFER LEWIS']},
    {"name":"NEXUS HORIZON CARRIERS LLC","addr":"1358 Airport Rd, PORTLAND, OR 66484","dot":"758434","ph":"(216) 441-7044","sups":['JESSICA SANCHEZ', 'DAVID JOHNSON', 'JOHN BROWN']},
    {"name":"CARGO CROWN HAULING ENTERPRISES LLC","addr":"7010 Westside Dr, MOBILE, AL 37711","dot":"2292257","ph":"(585) 838-4135","sups":['ANA CLARK', 'LUIS ROBINSON', 'ROBERT JONES']},
    {"name":"STERLING LOGISTICS CO","addr":"2252 Depot St, DENVER, CO 23366","dot":"1939692","ph":"(471) 500-5507","sups":['LINDA GONZALEZ', 'KAREN JOHNSON', 'DAVID THOMPSON']},
    {"name":"PHOENIX TRANSPORT LLC INC","addr":"4261 Industrial Way, LITTLE ROCK, AR 55217","dot":"3903646","ph":"(845) 808-5265","sups":['BARBARA RAMIREZ', 'LAURA PEREZ', 'WILLIAM JONES']},
    {"name":"AMERICAN FREIGHT SYSTEMS GROUP LLC","addr":"3082 Freight Way, LANSING, MI 54969","dot":"462877","ph":"(659) 950-8183","sups":['PATRICIA RAMIREZ', 'JOSE SANCHEZ', 'MIGUEL MILLER']},
    {"name":"USA SWIFT EXPRESS CO","addr":"4818 Airport Rd, DAYTON, OH 97588","dot":"539480","ph":"(402) 281-2784","sups":['SARAH GARCIA', 'JOSE THOMAS', 'THOMAS MARTIN']},
    {"name":"ROAD KING SHIPPING CO","addr":"4049 Southpoint Dr, SAN ANTONIO, TX 52022","dot":"1604274","ph":"(958) 453-4820","sups":['SARAH WILLIAMS', 'JOSE WILLIAMS', 'ROBERT TAYLOR']},
    {"name":"SILVER CROWN FREIGHT SYSTEMS LP","addr":"9840 Business Center Dr, FORT WORTH, TX 15409","dot":"3330398","ph":"(837) 336-2778","sups":['WILLIAM WILLIAMS', 'SOFIA ROBINSON', 'ELIZABETH PEREZ']},
    {"name":"HERNANDEZ CARRIERS INC LLC","addr":"1683 Fleet St, BATON ROUGE, LA 77110","dot":"2768608","ph":"(786) 325-2200","sups":['ANA WHITE', 'MARY JOHNSON', 'CARLOS PEREZ']},
    {"name":"VELOCITY COASTAL SHIPPING LLC","addr":"7309 Highway Dr, MINNEAPOLIS, MN 30608","dot":"3945236","ph":"(579) 832-6240","sups":['MIGUEL MARTIN', 'LUIS MARTIN', 'JESSICA WHITE']},
    {"name":"USA TRANSPORT LLC GROUP LLC","addr":"5864 Cargo Way, TOLEDO, OH 13888","dot":"2205859","ph":"(959) 722-1152","sups":['THOMAS SMITH', 'JAMES MILLER', 'DIANA WILLIAMS']},
    {"name":"TRAIL BLAZER TRUCKING HOLDINGS INC","addr":"3764 Enterprise Way, SHREVEPORT, LA 30227","dot":"2284174","ph":"(260) 678-6288","sups":['PATRICIA GONZALEZ', 'PATRICIA WILLIAMS', 'SOFIA PEREZ']},
    {"name":"FOUNDERS SHIPPING INC","addr":"4327 Business Center Dr, OMAHA, NE 47137","dot":"394887","ph":"(471) 578-9646","sups":['MARY WILLIAMS', 'RICHARD ROBINSON', 'PATRICIA GONZALEZ']},
    {"name":"PIONEER TRUCKING CO CORP","addr":"9162 Southpoint Dr, OKLAHOMA CITY, OK 71132","dot":"3302295","ph":"(723) 389-8634","sups":['LUIS SMITH', 'MARY WILLIAMS', 'ELIZABETH JONES']},
    {"name":"LEE TRANSPORT LP","addr":"5328 Broad St, ALBUQUERQUE, NM 76942","dot":"1745489","ph":"(614) 451-5703","sups":['BARBARA GARCIA', 'JAMES THOMPSON', 'JOSEPH ANDERSON']},
    {"name":"APEX STERLING EXPRESS ENTERPRISES LLC","addr":"5639 Southpoint Dr, ATLANTA, GA 12316","dot":"3946504","ph":"(504) 829-3543","sups":['BARBARA LEWIS', 'ROBERT PEREZ', 'PATRICIA HERNANDEZ']},
    {"name":"IRON LOGISTICS LLC CORP","addr":"4459 Main St, MCALLEN, TX 40558","dot":"3759231","ph":"(219) 560-3966","sups":['RICHARD SANCHEZ', 'SARAH MOORE', 'MIGUEL THOMPSON']},
    {"name":"HORIZON CROSS COUNTRY LOGISTICS INC","addr":"7856 Main St, DES MOINES, IA 48562","dot":"1309905","ph":"(887) 459-1312","sups":['JOHN THOMAS', 'JOSE BROWN', 'DIANA LEWIS']},
    {"name":"FRONTIER CATALYST FREIGHTWAYS HOLDINGS INC","addr":"6883 Eastgate Dr, SEATTLE, WA 41505","dot":"545345","ph":"(414) 408-3327","sups":['JESSICA CLARK', 'LUIS WILSON', 'BARBARA LEWIS']},
    {"name":"THOMPSON EXPRESS LP","addr":"6829 Highway Dr, FORT WORTH, TX 72794","dot":"3553092","ph":"(334) 499-6340","sups":['ROBERT MARTINEZ', 'ANTONIO GONZALEZ', 'ELIZABETH TAYLOR']},
    {"name":"CONTINENTAL TRUCKING CORP","addr":"1278 Business Center Dr, CHATTANOOGA, TN 40594","dot":"1517714","ph":"(953) 248-4456","sups":['MARY MILLER', 'MIGUEL LEWIS', 'ANA MOORE']},
    {"name":"XPO TRANSPORTATION ENTERPRISES LLC","addr":"3673 Broad St, TULSA, OK 70477","dot":"676356","ph":"(427) 564-1772","sups":['LINDA DAVIS', 'JAMES HERNANDEZ', 'JAMES LEWIS']},
    {"name":"IRON SHIPPING GROUP LLC","addr":"588 Airport Rd, SHREVEPORT, LA 62820","dot":"691397","ph":"(763) 598-1753","sups":['RICHARD LEWIS', 'LUIS ANDERSON', 'RICHARD WHITE']},
    {"name":"CATALYST LIBERTY BELL FREIGHTWAYS INC","addr":"1079 Logistics Blvd, SAN ANTONIO, TX 19648","dot":"274071","ph":"(493) 526-2245","sups":['JAMES LEE', 'RICHARD WILLIAMS', 'JOSEPH HERNANDEZ']},
    {"name":"FALCON CARRIERS INC","addr":"1179 Broad St, RENO, NV 98568","dot":"556429","ph":"(795) 865-1739","sups":['PATRICIA MARTIN', 'MARIA LOPEZ', 'SUSAN MOORE']},
    {"name":"FALCON FREIGHT SYSTEMS ENTERPRISES LLC","addr":"8423 Southpoint Dr, BOISE, ID 49599","dot":"765388","ph":"(492) 833-3241","sups":['RICHARD WILLIAMS', 'ANTONIO LOPEZ', 'ANA GONZALEZ']},
    {"name":"EASTERN TRANSPORT LLC INC","addr":"9389 Trucking Ln, OKLAHOMA CITY, OK 98920","dot":"3095780","ph":"(960) 453-3379","sups":['ANA WILSON', 'ROBERT LEWIS', 'WILLIAM JOHNSON']},
    {"name":"PATRIOT HEARTLAND FREIGHTWAYS GROUP LLC","addr":"9855 Industrial Pkwy, INDIANAPOLIS, IN 60275","dot":"1106662","ph":"(979) 807-5460","sups":['JENNIFER JACKSON', 'BARBARA RAMIREZ', 'MARY WILLIAMS']},
    {"name":"RODRIGUEZ LOGISTICS CORP","addr":"5887 Corporate Dr, DAYTON, OH 21322","dot":"1725222","ph":"(915) 629-3315","sups":['MARY JOHNSON', 'DIANA RAMIREZ', 'SOFIA TAYLOR']},
    {"name":"JB HUNT JB HUNT FREIGHT GROUP LLC","addr":"9709 Broad St, GREENSBORO, NC 22719","dot":"2856668","ph":"(509) 771-3429","sups":['LINDA ROBINSON', 'ANA GARCIA', 'MICHAEL THOMPSON']},
    {"name":"HERITAGE LOGISTICS GROUP LP","addr":"6040 Highway Dr, CHATTANOOGA, TN 71136","dot":"2701351","ph":"(289) 317-6580","sups":['CARLOS GONZALEZ', 'PATRICIA TAYLOR', 'BARBARA RODRIGUEZ']},
    {"name":"WERNER USA TRANSPORTATION GROUP LLC","addr":"952 Logistics Blvd, EL PASO, TX 65206","dot":"784947","ph":"(853) 263-2463","sups":['DAVID JACKSON', 'JOHN JACKSON', 'WILLIAM LOPEZ']},
    {"name":"ZENITH LOGISTICS LLC LLC","addr":"7301 Business Center Dr, ATLANTA, GA 43315","dot":"1530919","ph":"(336) 967-3328","sups":['DIANA WILSON', 'MICHAEL PEREZ', 'MARIA ANDERSON']},
    {"name":"LOPEZ HAULING LP","addr":"1132 Freight Way, CHARLOTTE, NC 52773","dot":"782684","ph":"(434) 709-6477","sups":['PATRICIA THOMPSON', 'KAREN RAMIREZ', 'JENNIFER RODRIGUEZ']},
    {"name":"COVENANT LOGISTICS GROUP HOLDINGS INC","addr":"1385 Southpoint Dr, FORT WORTH, TX 14545","dot":"341572","ph":"(244) 710-8570","sups":['BARBARA SANCHEZ', 'MARY LOPEZ', 'MARY TAYLOR']},
    {"name":"TRANS FREIGHT LLC","addr":"5594 Main St, BAKERSFIELD, CA 40078","dot":"152674","ph":"(899) 553-5045","sups":['JOSE THOMAS', 'SARAH LEE', 'CARLOS SMITH']},
    {"name":"MOUNTAIN CARRIERS ENTERPRISES LLC","addr":"5031 Corporate Dr, COLUMBUS, OH 12716","dot":"1935893","ph":"(950) 229-9722","sups":['JOHN SANCHEZ', 'JESSICA DAVIS', 'ANTONIO LEWIS']},
    {"name":"LOAD STAR UNITED LOGISTICS CO","addr":"3288 Freight Way, CORPUS CHRISTI, TX 78554","dot":"1788387","ph":"(954) 999-1494","sups":['LAURA RODRIGUEZ', 'RICHARD DAVIS', 'MARIA HERNANDEZ']},
    {"name":"JACKSON TRANSPORTATION LP","addr":"4914 Westside Dr, MILWAUKEE, WI 24357","dot":"1851929","ph":"(417) 705-5033","sups":['ANA WILLIAMS', 'JAMES LOPEZ', 'JOSEPH PEREZ']},
    {"name":"GONZALEZ LOGISTICS GROUP GROUP LLC","addr":"608 Depot St, BIRMINGHAM, AL 60812","dot":"279569","ph":"(263) 644-5386","sups":['ANTONIO WILSON', 'RICHARD MILLER', 'PATRICIA LEE']},
    {"name":"DIAMOND TRUCKING INC","addr":"9997 Freight Way, COLUMBIA, SC 96513","dot":"3993175","ph":"(368) 896-9063","sups":['ANA LEE', 'MARIA CLARK', 'KAREN WHITE']},
    {"name":"EAGLE LOGISTICS LLC ENTERPRISES LLC","addr":"550 Corporate Dr, KANSAS CITY, MO 49298","dot":"2309019","ph":"(249) 776-2706","sups":['JOSEPH PEREZ', 'ANA LOPEZ', 'MICHAEL THOMPSON']},
    {"name":"WILLIAMS TRANSPORT INC","addr":"9335 Eastgate Dr, MONTGOMERY, AL 84041","dot":"3391213","ph":"(643) 996-3944","sups":['SARAH MARTIN', 'CHARLES ROBINSON', 'DIANA MILLER']},
    {"name":"GONZALEZ TRUCKING CORP","addr":"2145 Industrial Way, TOLEDO, OH 24905","dot":"3484410","ph":"(777) 703-8153","sups":['MICHAEL LEE', 'WILLIAM MARTIN', 'MICHAEL WILLIAMS']},
    {"name":"TURNPIKE ZENITH TRUCKING CO LLC","addr":"5943 Trucking Ln, HOUSTON, TX 60982","dot":"1973991","ph":"(232) 728-1033","sups":['MICHAEL JACKSON', 'LINDA DAVIS', 'JAMES HARRIS']},
    {"name":"WILLIAMS FREIGHT LLC","addr":"4664 Industrial Pkwy, LANSING, MI 22687","dot":"3825002","ph":"(770) 829-1960","sups":['ROBERT PEREZ', 'CHARLES THOMPSON', 'SUSAN LEWIS']},
    {"name":"WILSON LOGISTICS GROUP CO","addr":"8477 Enterprise Way, ATLANTA, GA 16318","dot":"3686005","ph":"(829) 769-1288","sups":['LINDA MILLER', 'THOMAS RODRIGUEZ', 'JESSICA WHITE']},
    {"name":"HERITAGE LAKESIDE TRANSPORT SERVICES INC","addr":"2870 Business Center Dr, BIRMINGHAM, AL 60602","dot":"3468241","ph":"(276) 439-2834","sups":['BARBARA WHITE', 'SUSAN RODRIGUEZ', 'LINDA JACKSON']},
    {"name":"PIONEER TRANSPORT LLC CORP","addr":"3549 Commerce Dr, DES MOINES, IA 54240","dot":"3113920","ph":"(779) 758-6885","sups":['JESSICA GARCIA', 'JOSEPH MOORE', 'THOMAS SMITH']},
    {"name":"EXPRESS COVENANT TRANSPORT SERVICES HOLDINGS INC","addr":"266 Corporate Dr, CORPUS CHRISTI, TX 99787","dot":"676073","ph":"(509) 918-7363","sups":['DIANA HERNANDEZ', 'ANA RAMIREZ', 'ANA TAYLOR']},
    {"name":"WILSON FREIGHT SYSTEMS CORP","addr":"3639 Corporate Dr, FRESNO, CA 45161","dot":"911500","ph":"(703) 686-4535","sups":['JAMES GONZALEZ', 'SARAH JOHNSON', 'MARIA GONZALEZ']},
    {"name":"AMERICAN TRANSPORTATION HOLDINGS INC","addr":"5256 Northgate Blvd, KNOXVILLE, TN 15538","dot":"2693784","ph":"(618) 353-1097","sups":['ANTONIO MARTIN', 'CHARLES MILLER', 'MARY MILLER']},
    {"name":"EXPRESS FREIGHTWAYS LP","addr":"4670 Airport Rd, NASHVILLE, TN 89186","dot":"896536","ph":"(301) 335-2460","sups":['ELIZABETH WILLIAMS', 'THOMAS GARCIA', 'ANTONIO DAVIS']},
    {"name":"MOUNTAIN CARRIERS LP","addr":"3125 Enterprise Way, DALLAS, TX 77884","dot":"3723216","ph":"(904) 479-6578","sups":['MICHAEL PEREZ', 'JAMES SMITH', 'JESSICA SMITH']},
    {"name":"TURNPIKE TRANSPORT LLC CORP","addr":"8542 Westside Dr, EVANSVILLE, IN 24289","dot":"2187843","ph":"(548) 716-6018","sups":['MARY GARCIA', 'ANTONIO PEREZ', 'WILLIAM LEE']},
    {"name":"STAR EXPRESS CORP","addr":"4114 Fleet St, AUSTIN, TX 22031","dot":"2337052","ph":"(215) 608-7262","sups":['SOFIA RODRIGUEZ', 'ANA MARTINEZ', 'ELIZABETH GONZALEZ']},
    {"name":"GARCIA TRUCKING LP","addr":"1950 Trucking Ln, MEMPHIS, TN 71493","dot":"516760","ph":"(321) 813-2846","sups":['DIANA MARTINEZ', 'MICHAEL LEE', 'CARLOS PEREZ']},
    {"name":"APEX HAULING CORP","addr":"3646 Distribution Center Rd, GRAND RAPIDS, MI 51741","dot":"3915171","ph":"(308) 536-5702","sups":['JESSICA ROBINSON', 'MICHAEL RODRIGUEZ', 'JOHN MOORE']},
    {"name":"COASTAL LOGISTICS ENTERPRISES LLC","addr":"7534 Depot St, SPOKANE, WA 80801","dot":"485292","ph":"(426) 637-2306","sups":['LUIS JONES', 'JESSICA TAYLOR', 'SARAH GARCIA']},
    {"name":"JONES SHIPPING HOLDINGS INC","addr":"2427 Corporate Dr, DENVER, CO 62557","dot":"1468886","ph":"(920) 343-9811","sups":['ELIZABETH LOPEZ', 'CARLOS THOMAS', 'ROBERT SMITH']},
    {"name":"ZENITH HAULING HOLDINGS INC","addr":"9520 Corporate Dr, WICHITA, KS 12987","dot":"1759265","ph":"(357) 403-3323","sups":['JENNIFER WILSON', 'JESSICA MOORE', 'DAVID SMITH']},
    {"name":"TRAIL BLAZER COVENANT TRANSPORT SERVICES CO","addr":"9747 Park Ave, DENVER, CO 63247","dot":"3207256","ph":"(725) 403-8606","sups":['DIANA HARRIS', 'CHARLES DAVIS', 'SARAH MILLER']},
    {"name":"LIBERTY BELL SHIPPING LP","addr":"1069 Northgate Blvd, COLUMBIA, SC 40484","dot":"3848842","ph":"(905) 861-7228","sups":['BARBARA ROBINSON', 'LINDA THOMAS', 'THOMAS PEREZ']},
    {"name":"PATRIOT CARRIERS INC GROUP LLC","addr":"6461 Eastgate Dr, SAN ANTONIO, TX 13632","dot":"1344893","ph":"(249) 702-7021","sups":['JAMES JOHNSON', 'SUSAN MOORE', 'DIANA PEREZ']},
    {"name":"SMITH TRUCKING LP","addr":"7126 Corporate Dr, BOISE, ID 61128","dot":"2276299","ph":"(696) 805-5036","sups":['JAMES MARTIN', 'LUIS LEWIS', 'JENNIFER MARTINEZ']},
    {"name":"TITAN LINES INC","addr":"535 Highway Dr, SEATTLE, WA 90500","dot":"3276149","ph":"(774) 621-9426","sups":['MICHAEL WILSON', 'DIANA THOMPSON', 'JENNIFER RAMIREZ']},
    {"name":"LAKESIDE LOGISTICS GROUP ENTERPRISES LLC","addr":"7585 Terminal Rd, BAKERSFIELD, CA 44863","dot":"2206118","ph":"(217) 917-6701","sups":['DIANA BROWN', 'JOHN RAMIREZ', 'JAMES MILLER']},
    {"name":"WERNER LOGISTICS LLC HOLDINGS INC","addr":"2314 Main St, COLUMBIA, SC 16631","dot":"3147385","ph":"(202) 369-8923","sups":['LUIS WHITE', 'MICHAEL LEE', 'CHARLES WHITE']},
    {"name":"MOUNTAIN EXPRESS CO","addr":"8620 Enterprise Way, DES MOINES, IA 70784","dot":"2841837","ph":"(365) 597-8327","sups":['ANTONIO WILLIAMS', 'LUIS SMITH', 'LAURA ROBINSON']},
    {"name":"PIONEER PIONEER FREIGHT ENTERPRISES LLC","addr":"5217 Commerce Dr, LITTLE ROCK, AR 17271","dot":"1229648","ph":"(881) 860-8390","sups":['ROBERT MILLER', 'LAURA MARTIN', 'ANA DAVIS']},
    {"name":"MOUNTAIN CARRIERS INC LLC","addr":"344 Distribution Center Rd, SHREVEPORT, LA 79320","dot":"985675","ph":"(233) 474-9417","sups":['BARBARA SMITH', 'KAREN MILLER', 'SOFIA HERNANDEZ']},
    {"name":"LIBERTY SOUTHERN SHIPPING CO","addr":"2072 Southpoint Dr, DAYTON, OH 33291","dot":"2888941","ph":"(245) 881-5009","sups":['LUIS HARRIS', 'LUIS CLARK', 'JAMES WILSON']},
    {"name":"CARGO MASTER LINES GROUP LLC","addr":"9549 Depot St, COLUMBUS, OH 36016","dot":"1167263","ph":"(685) 653-9199","sups":['SUSAN GONZALEZ', 'CHARLES MILLER', 'SUSAN MILLER']},
    {"name":"EAGLE SHIPPING INC","addr":"4707 Westside Dr, SALT LAKE CITY, UT 95670","dot":"168732","ph":"(299) 313-3841","sups":['MARY WHITE', 'LINDA GARCIA', 'PATRICIA LOPEZ']},
    {"name":"SWIFT RUSH TRUCKING CO","addr":"3133 Freight Way, NASHVILLE, TN 90113","dot":"1179221","ph":"(658) 293-1506","sups":['JOHN MOORE', 'PATRICIA THOMPSON', 'JAMES SMITH']},
    {"name":"SANCHEZ FREIGHTWAYS CO","addr":"3888 Airport Rd, LUBBOCK, TX 66955","dot":"3638391","ph":"(554) 523-1480","sups":['JOSEPH LEWIS', 'KAREN RAMIREZ', 'ROBERT HARRIS']},
    {"name":"HEARTLAND TRUCKING CO HOLDINGS INC","addr":"1443 Northgate Blvd, BAKERSFIELD, CA 53272","dot":"181833","ph":"(565) 824-4673","sups":['KAREN RODRIGUEZ', 'JENNIFER MOORE', 'JENNIFER LEWIS']},
    {"name":"JONES TRANSPORT SERVICES INC","addr":"9547 Industrial Way, CHATTANOOGA, TN 45213","dot":"3012605","ph":"(543) 799-4787","sups":['JOSEPH CLARK', 'MICHAEL ANDERSON', 'JOSE PEREZ']},
    {"name":"MILLER LOGISTICS GROUP HOLDINGS INC","addr":"2605 Southpoint Dr, LAS VEGAS, NV 78582","dot":"677988","ph":"(978) 219-9755","sups":['JOSEPH JACKSON', 'ROBERT ROBINSON', 'LUIS ROBINSON']},
    {"name":"PLATINUM TRANSPORT LLC LLC","addr":"5805 Westside Dr, FORT WORTH, TX 37785","dot":"2694564","ph":"(689) 985-5559","sups":['SOFIA RODRIGUEZ', 'THOMAS SANCHEZ', 'DAVID WILSON']},
    {"name":"PREMIER HAULING LLC","addr":"5487 Northgate Blvd, JACKSON, MS 86096","dot":"2862473","ph":"(858) 337-8053","sups":['MICHAEL MARTIN', 'DAVID JACKSON', 'CARLOS BROWN']},
    {"name":"EAGLE TRUCKING CO INC","addr":"4828 Logistics Blvd, LUBBOCK, TX 37374","dot":"2690472","ph":"(951) 743-5114","sups":['ANA JONES', 'MICHAEL GARCIA', 'LINDA LOPEZ']},
    {"name":"MARTEN FREIGHT GROUP LLC","addr":"3631 Corporate Dr, DAYTON, OH 31758","dot":"790489","ph":"(460) 707-5598","sups":['RICHARD MOORE', 'MIGUEL MILLER', 'DIANA SANCHEZ']},
    {"name":"ROYAL DIAMOND FREIGHT SYSTEMS INC","addr":"8364 Airport Rd, AKRON, OH 14530","dot":"3821084","ph":"(209) 785-8134","sups":['SARAH RAMIREZ', 'THOMAS JACKSON', 'LUIS BROWN']},
    {"name":"CARGO DESERT FREIGHT INC","addr":"9166 Terminal Rd, AKRON, OH 63414","dot":"3993888","ph":"(388) 645-9897","sups":['DIANA WILSON', 'SARAH HERNANDEZ', 'KAREN SANCHEZ']},
    {"name":"WHITE FREIGHT SYSTEMS CO","addr":"7983 Commerce Dr, GREENSBORO, NC 83715","dot":"2021457","ph":"(855) 359-3352","sups":['SUSAN LEE', 'KAREN TAYLOR', 'ELIZABETH ROBINSON']},
    {"name":"CATALYST TRUCKING GROUP LLC","addr":"8951 Highway Dr, RICHMOND, VA 27184","dot":"2225598","ph":"(518) 577-8323","sups":['JAMES MILLER', 'SUSAN LOPEZ', 'WILLIAM WILLIAMS']},
    {"name":"ROEHL LOGISTICS GROUP INC","addr":"1474 Trucking Ln, OKLAHOMA CITY, OK 72477","dot":"495895","ph":"(822) 474-5118","sups":['LUIS WILLIAMS', 'JOHN RAMIREZ', 'LINDA DAVIS']},
    {"name":"CARGO MASTER CARRIERS INC","addr":"5168 Airport Rd, FORT WAYNE, IN 99385","dot":"3184210","ph":"(746) 778-9040","sups":['DAVID JOHNSON', 'LAURA THOMAS', 'BARBARA RODRIGUEZ']},
    {"name":"PHOENIX MOMENTUM CARRIERS HOLDINGS INC","addr":"3483 Westside Dr, EVANSVILLE, IN 58859","dot":"800768","ph":"(689) 757-4173","sups":['ANA JOHNSON', 'LINDA ANDERSON', 'SOFIA MARTINEZ']},
    {"name":"HIGHWAY BLUE SKY TRANSPORT GROUP LLC","addr":"1042 Broad St, ATLANTA, GA 96038","dot":"2234648","ph":"(368) 804-6666","sups":['BARBARA HARRIS', 'PATRICIA SMITH', 'ELIZABETH MARTIN']},
    {"name":"RED RIVER TRANSPORT LLC","addr":"7861 Highway Dr, ATLANTA, GA 82499","dot":"175103","ph":"(434) 986-5392","sups":['CHARLES RAMIREZ', 'JAMES WILSON', 'ROBERT JOHNSON']},
    {"name":"ROYAL CARGO MASTER CARRIERS CO","addr":"9684 Freight Way, BAKERSFIELD, CA 79835","dot":"2871537","ph":"(347) 946-1053","sups":['ANTONIO BROWN', 'ANA GONZALEZ', 'JOSEPH JOHNSON']},
    {"name":"STAR LOGISTICS CORP","addr":"5678 Broad St, JOPLIN, MO 87092","dot":"3570813","ph":"(594) 360-6866","sups":['DIANA GONZALEZ', 'ANTONIO DAVIS', 'SUSAN RODRIGUEZ']},
    {"name":"NATIONAL TRUCKING CO","addr":"2619 Logistics Blvd, CORPUS CHRISTI, TX 70015","dot":"2869106","ph":"(214) 701-3668","sups":['SOFIA SANCHEZ', 'JOSEPH JACKSON', 'LUIS HERNANDEZ']},
    {"name":"FRONTIER TRANSPORT GROUP LLC","addr":"6744 Westside Dr, SALT LAKE CITY, UT 79273","dot":"3698557","ph":"(393) 747-4443","sups":['SARAH LOPEZ', 'ROBERT TAYLOR', 'SARAH CLARK']},
    {"name":"XPO LOGISTICS GROUP HOLDINGS INC","addr":"842 Cargo Way, KANSAS CITY, MO 25487","dot":"1555616","ph":"(671) 886-6881","sups":['MICHAEL LOPEZ', 'DAVID WHITE', 'ROBERT THOMPSON']},
    {"name":"ROBINSON TRANSPORT SERVICES HOLDINGS INC","addr":"8495 Terminal Rd, BOISE, ID 49244","dot":"1857091","ph":"(725) 393-3994","sups":['SUSAN WHITE', 'ROBERT JACKSON', 'ANA PEREZ']},
    {"name":"TITAN TRUCKING CO GROUP LLC","addr":"2475 Eastgate Dr, OMAHA, NE 56185","dot":"2270224","ph":"(467) 720-9101","sups":['JENNIFER CLARK', 'MIGUEL THOMAS', 'CHARLES SMITH']},
    {"name":"NATIONAL FREIGHT CO","addr":"1317 Enterprise Way, TULSA, OK 86459","dot":"1504030","ph":"(460) 801-5842","sups":['ANTONIO JACKSON', 'THOMAS RODRIGUEZ', 'JOHN WILLIAMS']},
    {"name":"HEARTLAND TRANSPORT LLC","addr":"1031 Industrial Pkwy, LAREDO, TX 85554","dot":"2205619","ph":"(878) 746-9112","sups":['JOHN GONZALEZ', 'MICHAEL HERNANDEZ', 'ELIZABETH THOMPSON']},
    {"name":"GARCIA LOGISTICS GROUP HOLDINGS INC","addr":"3656 Airport Rd, CHARLOTTE, NC 23671","dot":"1406449","ph":"(263) 473-1436","sups":['JESSICA THOMAS', 'CARLOS MARTINEZ', 'JENNIFER GARCIA']},
    {"name":"VANGUARD AMERICAN HAULING LLC","addr":"1584 Westside Dr, SPOKANE, WA 59788","dot":"3662056","ph":"(651) 861-9260","sups":['LINDA ANDERSON', 'JOHN LOPEZ', 'RICHARD ANDERSON']},
    {"name":"LIBERTY LOGISTICS LLC LLC","addr":"6763 Business Center Dr, LOUISVILLE, KY 33472","dot":"2358321","ph":"(740) 454-7198","sups":['KAREN RODRIGUEZ', 'MARY MILLER', 'ROBERT TAYLOR']},
    {"name":"UNITED FREIGHT ENTERPRISES LLC","addr":"3870 Terminal Rd, DENVER, CO 72346","dot":"639846","ph":"(256) 974-4914","sups":['CARLOS JOHNSON', 'DAVID ANDERSON', 'JOSEPH WILSON']},
    {"name":"MOUNTAIN EXPRESS LLC","addr":"7292 Airport Rd, AMARILLO, TX 38920","dot":"114144","ph":"(724) 545-4101","sups":['CHARLES LEWIS', 'SARAH GONZALEZ', 'SUSAN JACKSON']},
    {"name":"SUMMIT PHOENIX HAULING CORP","addr":"8955 Enterprise Way, DALLAS, TX 46066","dot":"1777805","ph":"(244) 247-2443","sups":['RICHARD TAYLOR', 'ANA GARCIA', 'WILLIAM MOORE']},
    {"name":"FALCON FREIGHTWAYS LP","addr":"6781 Fleet St, HOUSTON, TX 81689","dot":"2871875","ph":"(860) 804-4055","sups":['SARAH TAYLOR', 'KAREN MARTIN', 'CHARLES SMITH']},
    {"name":"NORTHERN FREIGHT FREIGHTWAYS GROUP LLC","addr":"8828 Depot St, SEATTLE, WA 30914","dot":"3714064","ph":"(258) 333-3529","sups":['CHARLES ROBINSON', 'WILLIAM JONES', 'SARAH RODRIGUEZ']},
    {"name":"NEXUS LINES LLC","addr":"5917 Freight Way, LUBBOCK, TX 85890","dot":"1524378","ph":"(819) 617-4169","sups":['LAURA CLARK', 'WILLIAM JACKSON', 'DIANA MARTIN']},
    {"name":"HIGHWAY ALL AMERICAN SHIPPING HOLDINGS INC","addr":"8169 Corporate Dr, COLUMBUS, OH 67962","dot":"2524496","ph":"(826) 996-8375","sups":['JOSE THOMPSON', 'WILLIAM PEREZ', 'MARIA MOORE']},
    {"name":"PLATINUM CARGO MASTER EXPRESS LP","addr":"1085 Distribution Center Rd, WICHITA, KS 22941","dot":"3729809","ph":"(648) 590-8520","sups":['DAVID ANDERSON', 'JESSICA JOHNSON', 'ANA HARRIS']},
    {"name":"STEEL FREIGHT SYSTEMS HOLDINGS INC","addr":"9824 Freight Way, SALT LAKE CITY, UT 15814","dot":"182402","ph":"(921) 658-8840","sups":['JAMES CLARK', 'LINDA HERNANDEZ', 'JESSICA LEE']},
    {"name":"PATRIOT TRUCKING INC","addr":"2957 Cargo Way, BAKERSFIELD, CA 52547","dot":"2567717","ph":"(478) 218-2854","sups":['JENNIFER SMITH', 'CHARLES LEWIS', 'JAMES THOMAS']},
    {"name":"GONZALEZ EXPRESS GROUP LLC","addr":"1633 Corporate Dr, CORPUS CHRISTI, TX 91818","dot":"3438483","ph":"(497) 290-4406","sups":['THOMAS LEE', 'ANA WILSON', 'KAREN WILLIAMS']},
    {"name":"VANGUARD EXPRESS ENTERPRISES LLC","addr":"9455 Enterprise Way, MCALLEN, TX 94088","dot":"2093425","ph":"(322) 326-5578","sups":['THOMAS SMITH', 'DAVID THOMPSON', 'JOSE BROWN']},
    {"name":"EAGLE CONTINENTAL TRANSPORTATION ENTERPRISES LLC","addr":"2702 Main St, DENVER, CO 79778","dot":"306468","ph":"(796) 684-8993","sups":['MIGUEL DAVIS', 'DIANA GARCIA', 'KAREN HARRIS']},
    {"name":"ZENITH CARGO SHIPPING CO","addr":"2667 Distribution Center Rd, CHATTANOOGA, TN 82097","dot":"777820","ph":"(546) 620-8877","sups":['JOHN THOMAS', 'SARAH LEWIS', 'DAVID MARTIN']},
    {"name":"PHOENIX PACIFIC TRUCKING CO LLC","addr":"5538 Westside Dr, WICHITA, KS 71751","dot":"3927814","ph":"(303) 304-8689","sups":['RICHARD GARCIA', 'ANA TAYLOR', 'SARAH HERNANDEZ']},
    {"name":"RUSH FREIGHT GROUP LLC","addr":"6251 Logistics Blvd, SAN ANTONIO, TX 71569","dot":"610955","ph":"(722) 902-6382","sups":['SOFIA MARTINEZ', 'MIGUEL LOPEZ', 'MIGUEL MARTIN']},
    {"name":"HEARTLAND TRANSPORT CORP","addr":"1984 Airport Rd, SPOKANE, WA 52660","dot":"827538","ph":"(779) 561-9555","sups":['LUIS TAYLOR', 'PATRICIA LOPEZ', 'JOSE HERNANDEZ']},
    {"name":"HARRIS CARRIERS CORP","addr":"1536 Distribution Center Rd, AKRON, OH 26261","dot":"2015644","ph":"(217) 853-6291","sups":['ANTONIO WILSON', 'ROBERT DAVIS', 'SUSAN WILSON']},
    {"name":"TAYLOR TRANSPORT SERVICES GROUP LLC","addr":"2424 Trucking Ln, RICHMOND, VA 89423","dot":"3672345","ph":"(482) 450-9209","sups":['DIANA TAYLOR', 'CHARLES ROBINSON', 'BARBARA BROWN']},
    {"name":"BROWN TRUCKING LLC","addr":"9776 Industrial Way, SAN ANTONIO, TX 43054","dot":"2261929","ph":"(885) 342-6471","sups":['THOMAS MOORE', 'DAVID RODRIGUEZ', 'CHARLES MARTIN']},
    {"name":"HAWK CARRIERS LP","addr":"7801 Park Ave, LITTLE ROCK, AR 40117","dot":"336149","ph":"(494) 765-4527","sups":['JESSICA HARRIS', 'RICHARD HARRIS', 'SUSAN MILLER']},
    {"name":"ANDERSON TRUCKING ENTERPRISES LLC","addr":"7919 Industrial Way, HOUSTON, TX 61482","dot":"2505244","ph":"(258) 417-7404","sups":['SUSAN MARTIN', 'PATRICIA ROBINSON', 'LAURA RODRIGUEZ']},
    {"name":"ZENITH EXPRESS HOLDINGS INC","addr":"3009 Industrial Way, FORT WORTH, TX 42244","dot":"2466103","ph":"(855) 802-4810","sups":['DIANA THOMPSON', 'LUIS WILLIAMS', 'JOHN GARCIA']},
    {"name":"SMITH LOGISTICS LLC CORP","addr":"4197 Depot St, NASHVILLE, TN 82026","dot":"3410290","ph":"(621) 524-2788","sups":['JOSEPH HARRIS', 'MARIA RAMIREZ', 'SARAH RODRIGUEZ']},
    {"name":"CATALYST TRANSPORT LP","addr":"3033 Park Ave, BOISE, ID 68602","dot":"1581090","ph":"(608) 309-7731","sups":['LUIS WILSON', 'CHARLES ROBINSON', 'ELIZABETH JONES']},
    {"name":"COASTAL LINES LLC","addr":"9277 Distribution Center Rd, BOISE, ID 91849","dot":"3861026","ph":"(711) 819-6869","sups":['MIGUEL MOORE', 'SUSAN JONES', 'MICHAEL TAYLOR']},
    {"name":"ROBINSON LOGISTICS LLC GROUP LLC","addr":"7573 Commerce Dr, CHARLOTTE, NC 46508","dot":"3432439","ph":"(954) 419-4110","sups":['DIANA SMITH', 'MARIA RODRIGUEZ', 'SOFIA TAYLOR']},
    {"name":"ATLANTIC TRUCKING LLC","addr":"4955 Commerce Dr, CHARLOTTE, NC 77909","dot":"3269056","ph":"(859) 911-2343","sups":['THOMAS THOMAS', 'DIANA SANCHEZ', 'LUIS SANCHEZ']},
    {"name":"BLUE SKY ALL AMERICAN LOGISTICS LLC ENTERPRISES LLC","addr":"9029 Trucking Ln, LUBBOCK, TX 14185","dot":"1166207","ph":"(981) 318-5413","sups":['LAURA LEE', 'JOSEPH ROBINSON', 'JENNIFER LEWIS']},
    {"name":"JB HUNT FREIGHTWAYS GROUP LLC","addr":"2228 Industrial Way, MILWAUKEE, WI 82075","dot":"214216","ph":"(536) 736-8622","sups":['CHARLES LOPEZ', 'BARBARA JACKSON', 'LUIS JACKSON']},
    {"name":"FREIGHT LOGISTICS LP","addr":"634 Park Ave, COLUMBIA, SC 63580","dot":"367372","ph":"(349) 436-6954","sups":['JAMES CLARK', 'KAREN DAVIS', 'PATRICIA TAYLOR']},
    {"name":"DIAMOND CARRIERS LP","addr":"7621 Distribution Center Rd, ATLANTA, GA 98776","dot":"1354826","ph":"(511) 907-7233","sups":['JOSE ROBINSON', 'JOSEPH JOHNSON', 'LUIS GONZALEZ']},
    {"name":"FOUNDERS STAR TRANSPORTATION HOLDINGS INC","addr":"9612 Westside Dr, ALBUQUERQUE, NM 72063","dot":"3984487","ph":"(334) 663-2748","sups":['PATRICIA MILLER', 'SOFIA RODRIGUEZ', 'CARLOS PEREZ']},
    {"name":"EXPRESS SHIPPING ENTERPRISES LLC","addr":"2121 Highway Dr, AUSTIN, TX 57496","dot":"1237056","ph":"(615) 594-2177","sups":['CARLOS JOHNSON', 'DAVID HARRIS', 'DAVID DAVIS']},
    {"name":"VANGUARD MOMENTUM CARRIERS GROUP LLC","addr":"7030 Southpoint Dr, RICHMOND, VA 51916","dot":"2238380","ph":"(675) 202-1952","sups":['DIANA JOHNSON', 'MARIA MARTINEZ', 'CHARLES GARCIA']},
    {"name":"CLARK CARRIERS LP","addr":"8592 Logistics Blvd, DES MOINES, IA 98024","dot":"1227482","ph":"(989) 208-3463","sups":['THOMAS MARTIN', 'LAURA MILLER', 'MICHAEL WHITE']},
    {"name":"SWIFT LIBERTY BELL TRANSPORTATION CO","addr":"675 Distribution Center Rd, MINNEAPOLIS, MN 73285","dot":"3527915","ph":"(526) 766-9928","sups":['PATRICIA LEWIS', 'ELIZABETH RAMIREZ', 'JENNIFER THOMPSON']},
    {"name":"COASTAL TRUCKING CO CO","addr":"2884 Park Ave, AUSTIN, TX 82511","dot":"3565691","ph":"(426) 479-4570","sups":['THOMAS WILSON', 'PATRICIA SANCHEZ', 'MIGUEL THOMAS']},
    {"name":"BLUE SKY MIDWEST TRANSPORT SERVICES CO","addr":"260 Corporate Dr, AMARILLO, TX 17153","dot":"754333","ph":"(470) 284-3588","sups":['ANA RAMIREZ', 'JOSE BROWN', 'JOSEPH ANDERSON']},
    {"name":"PLATINUM TRANSPORT SERVICES ENTERPRISES LLC","addr":"2659 Industrial Pkwy, FRESNO, CA 22662","dot":"287769","ph":"(364) 635-1020","sups":['MIGUEL SANCHEZ', 'JESSICA LEWIS', 'JAMES RODRIGUEZ']},
    {"name":"AMERICAN TRANSPORT SERVICES ENTERPRISES LLC","addr":"8061 Cargo Way, MCALLEN, TX 34620","dot":"3212382","ph":"(646) 259-4865","sups":['SUSAN GONZALEZ', 'KAREN ROBINSON', 'CHARLES LEWIS']},
    {"name":"WESTERN TRANSPORT LLC ENTERPRISES LLC","addr":"3763 Southpoint Dr, BATON ROUGE, LA 29174","dot":"2531326","ph":"(602) 714-1194","sups":['PATRICIA THOMPSON', 'JENNIFER SANCHEZ', 'LUIS MILLER']},
    {"name":"GONZALEZ FREIGHT CORP","addr":"4781 Broad St, PHOENIX, AZ 87160","dot":"3754089","ph":"(235) 549-1711","sups":['ELIZABETH DAVIS', 'DIANA TAYLOR', 'JOHN WILLIAMS']},
    {"name":"RODRIGUEZ TRANSPORT LLC CORP","addr":"3501 Freight Way, SALT LAKE CITY, UT 45484","dot":"2493559","ph":"(268) 423-3538","sups":['ROBERT BROWN', 'LAURA RODRIGUEZ', 'SUSAN THOMAS']},
    {"name":"XPO TRANSPORT LLC CORP","addr":"3591 Cargo Way, MOBILE, AL 53988","dot":"372146","ph":"(296) 396-3924","sups":['RICHARD RAMIREZ', 'BARBARA THOMAS', 'DAVID MARTINEZ']},
    {"name":"WILLIAMS HAULING LP","addr":"5210 Distribution Center Rd, LAS VEGAS, NV 96236","dot":"3633765","ph":"(508) 508-5930","sups":['THOMAS BROWN', 'SUSAN WILSON', 'CARLOS CLARK']},
    {"name":"PHOENIX SHIPPING CORP","addr":"1251 Broad St, BOISE, ID 65054","dot":"2453252","ph":"(335) 414-2562","sups":['ANTONIO JONES', 'JESSICA GONZALEZ', 'LUIS DAVIS']},
    {"name":"WESTERN FREIGHTWAYS HOLDINGS INC","addr":"4688 Eastgate Dr, MEMPHIS, TN 23856","dot":"3513967","ph":"(538) 378-9943","sups":['RICHARD THOMAS', 'ELIZABETH WILLIAMS', 'JOSE PEREZ']},
    {"name":"NEXUS CROSS COUNTRY SHIPPING ENTERPRISES LLC","addr":"3216 Northgate Blvd, DALLAS, TX 75071","dot":"1481626","ph":"(414) 654-2505","sups":['KAREN BROWN', 'JOSE THOMAS', 'SOFIA MARTINEZ']},
    {"name":"SCHNEIDER FREIGHTWAYS CO","addr":"7534 Fleet St, BOISE, ID 75990","dot":"891991","ph":"(329) 985-2706","sups":['THOMAS GARCIA', 'CARLOS TAYLOR', 'DIANA RAMIREZ']},
    {"name":"EAGLE FREIGHT SYSTEMS CORP","addr":"4693 Park Ave, LUBBOCK, TX 55755","dot":"2221086","ph":"(428) 529-8595","sups":['SARAH SMITH', 'MARY CLARK', 'LUIS JOHNSON']},
    {"name":"RODRIGUEZ FREIGHT CO","addr":"1476 Commerce Dr, BIRMINGHAM, AL 97186","dot":"420667","ph":"(534) 463-2929","sups":['JOSE MILLER', 'SOFIA WILLIAMS', 'JOSE BROWN']},
    {"name":"PATRIOT SHIPPING HOLDINGS INC","addr":"7637 Westside Dr, JOPLIN, MO 61864","dot":"497957","ph":"(912) 601-2467","sups":['MARIA THOMAS', 'MARY TAYLOR', 'WILLIAM TAYLOR']},
    {"name":"WHITE TRANSPORT LLC HOLDINGS INC","addr":"3779 Highway Dr, ALBUQUERQUE, NM 85165","dot":"700708","ph":"(360) 628-3632","sups":['MIGUEL MARTINEZ', 'MICHAEL LEE', 'LINDA THOMAS']},
    {"name":"STEEL SHIPPING ENTERPRISES LLC","addr":"9192 Distribution Center Rd, CHATTANOOGA, TN 82591","dot":"714548","ph":"(785) 984-9729","sups":['MARIA SMITH', 'JOSEPH GONZALEZ', 'ELIZABETH LOPEZ']},
    {"name":"STERLING LINES LLC","addr":"4475 Airport Rd, INDIANAPOLIS, IN 99169","dot":"1962105","ph":"(215) 339-5804","sups":['THOMAS RODRIGUEZ', 'ELIZABETH LOPEZ', 'LUIS WILSON']},
    {"name":"HEARTLAND LINES CORP","addr":"2887 Business Center Dr, AKRON, OH 16256","dot":"2297485","ph":"(354) 368-2357","sups":['SUSAN MOORE', 'JENNIFER MOORE', 'MARY JOHNSON']},
    {"name":"MARTEN JB HUNT LOGISTICS GROUP LP","addr":"892 Broad St, CORPUS CHRISTI, TX 19189","dot":"2647635","ph":"(499) 624-9245","sups":['JOSEPH LEE', 'LAURA RODRIGUEZ', 'SOFIA HERNANDEZ']},
    {"name":"CONTINENTAL MARTEN FREIGHT ENTERPRISES LLC","addr":"9821 Logistics Blvd, SEATTLE, WA 77348","dot":"3836993","ph":"(625) 969-8915","sups":['LAURA HERNANDEZ', 'DAVID MILLER', 'SUSAN THOMAS']},
    {"name":"PLATINUM SWIFT SHIPPING LP","addr":"6774 Cargo Way, JACKSON, MS 91306","dot":"2129888","ph":"(540) 554-7933","sups":['DAVID GONZALEZ', 'WILLIAM HARRIS', 'JENNIFER RODRIGUEZ']},
    {"name":"LAKESIDE FREIGHT SYSTEMS INC","addr":"7109 Broad St, PHOENIX, AZ 94147","dot":"2426063","ph":"(225) 443-4851","sups":['LINDA MOORE', 'BARBARA JOHNSON', 'JOSE GARCIA']},
    {"name":"APEX CARRIERS INC LLC","addr":"4488 Industrial Pkwy, TOLEDO, OH 19369","dot":"3776770","ph":"(300) 898-3643","sups":['ANA MILLER', 'LINDA WILLIAMS', 'JAMES JOHNSON']},
    {"name":"FREEDOM FOUNDERS LOGISTICS GROUP LLC","addr":"8850 Logistics Blvd, MEMPHIS, TN 57319","dot":"3653175","ph":"(462) 919-8955","sups":['KAREN PEREZ', 'ROBERT ROBINSON', 'LAURA SMITH']},
    {"name":"HERNANDEZ LOGISTICS LLC GROUP LLC","addr":"2123 Depot St, WICHITA, KS 72067","dot":"439175","ph":"(978) 758-4500","sups":['SOFIA GARCIA', 'JAMES HARRIS', 'PATRICIA MARTIN']},
    {"name":"PATRIOT EXPRESS CO","addr":"1092 Commerce Dr, DES MOINES, IA 54019","dot":"685832","ph":"(615) 595-7991","sups":['DIANA JONES', 'DAVID GARCIA', 'ANA ROBINSON']},
    {"name":"JOHNSON LOGISTICS GROUP LLC","addr":"2625 Main St, MONTGOMERY, AL 35357","dot":"3682074","ph":"(791) 419-5949","sups":['RICHARD CLARK', 'JAMES RAMIREZ', 'MARIA ROBINSON']},
    {"name":"DESERT TRANSPORT GROUP LLC","addr":"8976 Park Ave, AUSTIN, TX 68678","dot":"306595","ph":"(616) 619-7482","sups":['SOFIA GARCIA', 'JOSEPH THOMPSON', 'JAMES TAYLOR']},
    {"name":"JONES TRANSPORT SERVICES HOLDINGS INC","addr":"3715 Eastgate Dr, MONTGOMERY, AL 34879","dot":"3227464","ph":"(815) 488-8316","sups":['ANA JOHNSON', 'LINDA ROBINSON', 'CARLOS PEREZ']},
    {"name":"USA CARRIERS ENTERPRISES LLC","addr":"3494 Broad St, CHATTANOOGA, TN 90538","dot":"1706724","ph":"(963) 576-1726","sups":['RICHARD WHITE', 'JAMES MARTINEZ', 'CHARLES WILSON']},
    {"name":"GOLD ZENITH TRANSPORTATION LLC","addr":"6654 Enterprise Way, PORTLAND, OR 69941","dot":"858248","ph":"(696) 354-3668","sups":['LAURA JACKSON', 'MICHAEL RAMIREZ', 'ANA WILSON']},
    {"name":"SCHNEIDER LOGISTICS LP","addr":"5346 Commerce Dr, OMAHA, NE 62434","dot":"1147268","ph":"(798) 715-1758","sups":['PATRICIA BROWN', 'RICHARD TAYLOR', 'RICHARD JONES']},
    {"name":"NORTHERN ZENITH LOGISTICS CORP","addr":"9030 Fleet St, EL PASO, TX 60048","dot":"677534","ph":"(376) 413-2059","sups":['ELIZABETH PEREZ', 'LINDA THOMAS', 'JOSEPH JACKSON']},
    {"name":"LEWIS FREIGHTWAYS INC","addr":"4039 Fleet St, DENVER, CO 25872","dot":"731796","ph":"(938) 736-3261","sups":['ELIZABETH BROWN', 'JOSEPH THOMAS', 'LINDA MOORE']},
    {"name":"RAMIREZ TRUCKING CO CORP","addr":"2449 Southpoint Dr, MONTGOMERY, AL 52962","dot":"3013603","ph":"(374) 833-7567","sups":['SARAH RODRIGUEZ', 'BARBARA ANDERSON', 'JAMES MARTIN']},
    {"name":"LOPEZ LINES GROUP LLC","addr":"6901 Business Center Dr, BATON ROUGE, LA 42989","dot":"2275093","ph":"(785) 896-8513","sups":['MARIA PEREZ', 'LUIS MILLER', 'SARAH WHITE']},
    {"name":"RAMIREZ LOGISTICS GROUP INC","addr":"6200 Trucking Ln, OMAHA, NE 60849","dot":"912818","ph":"(736) 767-1253","sups":['LUIS GONZALEZ', 'ANA WILSON', 'PATRICIA MOORE']},
    {"name":"CROWN FREIGHT GROUP LLC","addr":"3359 Enterprise Way, LITTLE ROCK, AR 22849","dot":"418904","ph":"(639) 311-8996","sups":['ANTONIO LOPEZ', 'SARAH SMITH', 'SOFIA LEE']},
    {"name":"ESTES HAULING INC","addr":"7689 Westside Dr, LAS VEGAS, NV 92927","dot":"1414010","ph":"(273) 652-3399","sups":['CHARLES THOMPSON', 'MARY LOPEZ', 'PATRICIA MOORE']},
    {"name":"FRONTIER PLATINUM LOGISTICS INC","addr":"5406 Northgate Blvd, EL PASO, TX 70156","dot":"1473094","ph":"(216) 482-8298","sups":['WILLIAM JACKSON', 'ROBERT MOORE', 'LUIS LEE']},
    {"name":"HIGHWAY RUSH TRANSPORT LLC","addr":"3612 Northgate Blvd, SHREVEPORT, LA 75083","dot":"240516","ph":"(965) 324-9804","sups":['SOFIA ANDERSON', 'MARIA JACKSON', 'MARY ANDERSON']},
    {"name":"VELOCITY COVENANT CARRIERS INC ENTERPRISES LLC","addr":"7630 Highway Dr, MOBILE, AL 22367","dot":"3878505","ph":"(281) 972-8175","sups":['JOSE GARCIA', 'SOFIA JONES', 'PATRICIA WHITE']},
    {"name":"DIAMOND AMERICAN TRANSPORT LLC HOLDINGS INC","addr":"7583 Broad St, DENVER, CO 15728","dot":"729239","ph":"(516) 513-6401","sups":['CARLOS DAVIS', 'LUIS BROWN', 'JOSE LOPEZ']},
    {"name":"GOLD WERNER LOGISTICS LLC CO","addr":"4596 Broad St, EL PASO, TX 41501","dot":"341656","ph":"(482) 763-9516","sups":['WILLIAM ROBINSON', 'SOFIA JOHNSON', 'THOMAS ROBINSON']},
    {"name":"INDEPENDENCE EXPRESS TRANSPORT SERVICES CO","addr":"2010 Enterprise Way, SPOKANE, WA 30126","dot":"2641563","ph":"(774) 580-4500","sups":['JOSEPH ANDERSON', 'JOSE GARCIA', 'WILLIAM JONES']},
    {"name":"ESTES TRANSPORT HOLDINGS INC","addr":"6686 Industrial Pkwy, KANSAS CITY, MO 96442","dot":"3543059","ph":"(816) 483-9697","sups":['SOFIA CLARK', 'BARBARA MARTIN', 'JOHN MILLER']},
    {"name":"GOLD TRANSPORT LLC HOLDINGS INC","addr":"6880 Corporate Dr, MOBILE, AL 40815","dot":"2799073","ph":"(315) 226-5956","sups":['JENNIFER THOMAS', 'PATRICIA GONZALEZ', 'JAMES BROWN']},
    {"name":"TRAIL BLAZER CARRIERS INC","addr":"714 Terminal Rd, CORPUS CHRISTI, TX 59249","dot":"3433146","ph":"(825) 277-3195","sups":['JAMES CLARK', 'JOSEPH SANCHEZ', 'LUIS GARCIA']},
    {"name":"STERLING TRANSPORT GROUP LLC","addr":"7118 Enterprise Way, RICHMOND, VA 75303","dot":"2318891","ph":"(742) 392-6302","sups":['SUSAN JONES', 'SARAH DAVIS', 'CHARLES HERNANDEZ']},
    {"name":"MIDWEST LOGISTICS LP","addr":"4296 Eastgate Dr, SEATTLE, WA 70100","dot":"3205294","ph":"(331) 399-2099","sups":['BARBARA MOORE', 'ANTONIO MARTINEZ', 'CHARLES LOPEZ']},
    {"name":"INTERSTATE STAR TRANSPORTATION LLC","addr":"313 Corporate Dr, SHREVEPORT, LA 60388","dot":"1442261","ph":"(891) 451-2941","sups":['BARBARA HERNANDEZ', 'JOHN TAYLOR', 'THOMAS MILLER']},
    {"name":"ATLANTIC SOUTHERN LOGISTICS GROUP LLC","addr":"6029 Cargo Way, CHARLOTTE, NC 30254","dot":"1465492","ph":"(652) 946-7083","sups":['ANA ANDERSON', 'MARY RAMIREZ', 'JOSE HARRIS']},
    {"name":"CARGO MASTER TRANS CARRIERS ENTERPRISES LLC","addr":"532 Enterprise Way, LOUISVILLE, KY 67557","dot":"2245405","ph":"(747) 751-7997","sups":['DAVID MARTIN', 'JESSICA HERNANDEZ', 'JOHN ROBINSON']},
    {"name":"WESTERN AMERICAN LOGISTICS GROUP HOLDINGS INC","addr":"1438 Park Ave, SAN ANTONIO, TX 77645","dot":"1334393","ph":"(617) 650-3502","sups":['ELIZABETH MOORE', 'LUIS LOPEZ', 'DIANA RAMIREZ']},
    {"name":"CARGO MASTER TRANSPORT ENTERPRISES LLC","addr":"2736 Freight Way, ALBUQUERQUE, NM 99908","dot":"1557795","ph":"(800) 504-2345","sups":['LUIS RAMIREZ', 'SARAH THOMPSON', 'MIGUEL WILSON']},
    {"name":"PACIFIC RED RIVER FREIGHT SYSTEMS CORP","addr":"5258 Freight Way, CHATTANOOGA, TN 44310","dot":"3311156","ph":"(595) 967-8072","sups":['THOMAS JONES', 'KAREN PEREZ', 'SOFIA JOHNSON']},
    {"name":"STERLING LOGISTICS GROUP LLC","addr":"2330 Westside Dr, JACKSON, MS 65563","dot":"997746","ph":"(515) 689-5748","sups":['PATRICIA MOORE', 'JAMES HERNANDEZ', 'SARAH BROWN']},
    {"name":"LAKESIDE MOUNTAIN CARRIERS INC ENTERPRISES LLC","addr":"2077 Park Ave, RICHMOND, VA 32996","dot":"2212952","ph":"(509) 409-4531","sups":['LAURA MILLER', 'CHARLES JONES', 'DIANA RAMIREZ']},
    {"name":"PLATINUM USA TRANSPORTATION ENTERPRISES LLC","addr":"7199 Westside Dr, FORT WORTH, TX 44117","dot":"308959","ph":"(686) 299-5025","sups":['LINDA MILLER', 'DIANA DAVIS', 'WILLIAM HERNANDEZ']},
    {"name":"ALL AMERICAN MIDWEST TRANSPORT ENTERPRISES LLC","addr":"1070 Terminal Rd, EVANSVILLE, IN 50960","dot":"2096180","ph":"(984) 400-6790","sups":['JOSEPH LEWIS', 'MICHAEL WHITE', 'DIANA JONES']},
    {"name":"GOLD CARRIERS INC HOLDINGS INC","addr":"1172 Eastgate Dr, BIRMINGHAM, AL 86074","dot":"3856325","ph":"(798) 309-9674","sups":['ANTONIO THOMPSON', 'JOHN CLARK', 'MICHAEL JACKSON']},
    {"name":"BROWN FREIGHT CO","addr":"3569 Airport Rd, AKRON, OH 57676","dot":"1287886","ph":"(862) 635-1376","sups":['THOMAS LEWIS', 'DIANA HARRIS', 'MIGUEL TAYLOR']},
    {"name":"SMITH LINES CO","addr":"6874 Industrial Way, MOBILE, AL 49576","dot":"3476457","ph":"(963) 690-6903","sups":['MIGUEL WHITE', 'PATRICIA ROBINSON', 'BARBARA WHITE']},
    {"name":"IRON AMERICAN LOGISTICS LLC CORP","addr":"3643 Logistics Blvd, GRAND RAPIDS, MI 72083","dot":"2517413","ph":"(522) 316-6463","sups":['PATRICIA THOMPSON', 'JAMES RAMIREZ', 'JAMES DAVIS']},
    {"name":"RED RIVER LOGISTICS LLC GROUP LLC","addr":"3555 Industrial Pkwy, ALBUQUERQUE, NM 30054","dot":"2554911","ph":"(877) 599-5315","sups":['LAURA CLARK', 'ROBERT MARTIN', 'MARY JONES']},
    {"name":"ANDERSON EXPRESS LLC","addr":"7056 Airport Rd, ATLANTA, GA 38871","dot":"584545","ph":"(813) 476-3720","sups":['JENNIFER BROWN', 'PATRICIA TAYLOR', 'MARY PEREZ']},
    {"name":"XPO DIAMOND EXPRESS LP","addr":"4616 Industrial Pkwy, DES MOINES, IA 27793","dot":"916387","ph":"(263) 785-1406","sups":['CARLOS RODRIGUEZ', 'JOHN MARTIN', 'JOHN SMITH']},
    {"name":"MOMENTUM CARRIERS HOLDINGS INC","addr":"6627 Business Center Dr, SHREVEPORT, LA 28468","dot":"640741","ph":"(223) 857-3225","sups":['CHARLES DAVIS', 'KAREN JONES', 'JESSICA CLARK']},
    {"name":"MARTINEZ TRANSPORT LLC HOLDINGS INC","addr":"5648 Commerce Dr, HOUSTON, TX 55324","dot":"3504261","ph":"(569) 324-5163","sups":['JOSE TAYLOR', 'JENNIFER GONZALEZ', 'PATRICIA ROBINSON']},
    {"name":"MILLER HAULING INC","addr":"6173 Commerce Dr, SAN ANTONIO, TX 56832","dot":"2640040","ph":"(778) 536-6085","sups":['JOSE MOORE', 'ROBERT MOORE', 'ELIZABETH RAMIREZ']},
    {"name":"PLAINS LINES ENTERPRISES LLC","addr":"7493 Eastgate Dr, CHICAGO, IL 68886","dot":"3164418","ph":"(380) 363-5885","sups":['JOHN MARTIN', 'KAREN MARTINEZ', 'ANA GARCIA']},
    {"name":"SWIFT FREIGHT SYSTEMS CORP","addr":"7502 Terminal Rd, RICHMOND, VA 10144","dot":"1733328","ph":"(597) 295-9059","sups":['LAURA SMITH', 'MARY WILSON', 'JENNIFER HARRIS']},
    {"name":"SYNERGY CARRIERS INC LP","addr":"6313 Corporate Dr, DAYTON, OH 70926","dot":"2677789","ph":"(841) 489-6473","sups":['LINDA TAYLOR', 'SARAH DAVIS', 'SUSAN WILLIAMS']},
    {"name":"WESTERN LINES INC","addr":"1705 Main St, DALLAS, TX 34738","dot":"3205498","ph":"(732) 597-1309","sups":['JENNIFER CLARK', 'RICHARD THOMAS', 'SOFIA RAMIREZ']},
    {"name":"FOUNDERS TRANSPORT LLC CO","addr":"3603 Distribution Center Rd, MOBILE, AL 45580","dot":"2146723","ph":"(823) 506-1662","sups":['MIGUEL LEWIS', 'ANA WILSON', 'ANA LOPEZ']},
    {"name":"LEGACY TRUCKING LP","addr":"3970 Commerce Dr, AKRON, OH 60032","dot":"1043674","ph":"(467) 913-7616","sups":['MARIA RAMIREZ', 'DIANA SMITH', 'MARIA ANDERSON']},
    {"name":"PEREZ LOGISTICS LLC HOLDINGS INC","addr":"7895 Eastgate Dr, CHARLOTTE, NC 65139","dot":"3088179","ph":"(361) 837-7461","sups":['JOHN MILLER', 'SARAH RAMIREZ', 'JOSE GONZALEZ']},
    {"name":"BLUE SKY TRANSPORTATION LP","addr":"1391 Trucking Ln, TOLEDO, OH 81637","dot":"1647793","ph":"(210) 787-8407","sups":['JENNIFER ROBINSON', 'JOHN MARTINEZ', 'PATRICIA THOMAS']},
    {"name":"INDEPENDENCE TRANSPORT SERVICES HOLDINGS INC","addr":"870 Terminal Rd, DAYTON, OH 16864","dot":"139894","ph":"(983) 573-3000","sups":['ANTONIO JACKSON', 'JOHN WILLIAMS', 'BARBARA SMITH']},
    {"name":"HIGHWAY SHIPPING LP","addr":"3918 Trucking Ln, LANSING, MI 34561","dot":"296095","ph":"(248) 337-2517","sups":['JOSE SANCHEZ', 'SUSAN JONES', 'MIGUEL PEREZ']},
    {"name":"TRANS PACIFIC FREIGHT SYSTEMS LLC","addr":"1928 Corporate Dr, SAN ANTONIO, TX 55562","dot":"1623040","ph":"(372) 693-3789","sups":['JOSE MOORE', 'CARLOS BROWN', 'JOSE GARCIA']},
    {"name":"LIBERTY KNIGHT LOGISTICS HOLDINGS INC","addr":"5179 Enterprise Way, HOUSTON, TX 83243","dot":"2260765","ph":"(831) 372-6031","sups":['ROBERT GONZALEZ', 'THOMAS JACKSON', 'DAVID MILLER']},
    {"name":"STERLING COASTAL EXPRESS ENTERPRISES LLC","addr":"9293 Distribution Center Rd, RENO, NV 37701","dot":"3124109","ph":"(267) 818-4815","sups":['JENNIFER THOMPSON', 'ANTONIO WHITE', 'ROBERT WILLIAMS']},
    {"name":"RAMIREZ TRANSPORT SERVICES CORP","addr":"1135 Park Ave, MILWAUKEE, WI 55226","dot":"2216285","ph":"(447) 614-2808","sups":['JAMES DAVIS', 'WILLIAM BROWN', 'MICHAEL LEE']},
    {"name":"PACIFIC HAULING CO","addr":"4739 Northgate Blvd, MEMPHIS, TN 67702","dot":"3984417","ph":"(595) 445-4167","sups":['DIANA CLARK', 'SUSAN JONES', 'SARAH GONZALEZ']},
    {"name":"PIONEER TRANSPORTATION LLC","addr":"3460 Corporate Dr, LANSING, MI 13754","dot":"2593240","ph":"(683) 947-6063","sups":['MARY MARTINEZ', 'JAMES ANDERSON', 'JOSE LEWIS']},
    {"name":"APEX TRUCKING ENTERPRISES LLC","addr":"4206 Airport Rd, CHATTANOOGA, TN 60581","dot":"3593109","ph":"(487) 417-8597","sups":['JESSICA LOPEZ', 'KAREN CLARK', 'MARY SANCHEZ']},
    {"name":"PREMIER SHIPPING CO","addr":"8045 Commerce Dr, OMAHA, NE 30105","dot":"1715925","ph":"(767) 639-8946","sups":['ROBERT LEWIS', 'JESSICA TAYLOR', 'DAVID BROWN']},
    {"name":"PLAINS TRANSPORT SERVICES CO","addr":"7956 Enterprise Way, JACKSON, MS 50295","dot":"1692540","ph":"(608) 606-8720","sups":['WILLIAM JONES', 'MICHAEL THOMPSON', 'MARY RODRIGUEZ']},
    {"name":"LOPEZ CARRIERS INC","addr":"2966 Commerce Dr, LUBBOCK, TX 57096","dot":"492818","ph":"(208) 437-4315","sups":['RICHARD SMITH', 'MARIA ANDERSON', 'CARLOS TAYLOR']},
    {"name":"ROYAL SWIFT HAULING HOLDINGS INC","addr":"3107 Corporate Dr, KANSAS CITY, MO 77007","dot":"3116357","ph":"(434) 745-1239","sups":['CARLOS GONZALEZ', 'JOSEPH MARTIN', 'RICHARD WILSON']},
    {"name":"SILVER CARRIERS INC CO","addr":"4451 Airport Rd, KNOXVILLE, TN 17065","dot":"913992","ph":"(249) 797-5196","sups":['JESSICA ROBINSON', 'BARBARA JOHNSON', 'MIGUEL HARRIS']},
    {"name":"PEREZ TRANSPORT LLC","addr":"6194 Terminal Rd, BAKERSFIELD, CA 73024","dot":"2332524","ph":"(440) 349-7934","sups":['ROBERT CLARK', 'MIGUEL JOHNSON', 'BARBARA DAVIS']},
    {"name":"INDEPENDENCE TRANSPORTATION GROUP LLC","addr":"802 Westside Dr, CORPUS CHRISTI, TX 77521","dot":"2514549","ph":"(372) 397-2832","sups":['LINDA WHITE', 'JOSE HERNANDEZ', 'JOHN ANDERSON']},
    {"name":"ALL AMERICAN TRUCKING CO ENTERPRISES LLC","addr":"8922 Industrial Way, AMARILLO, TX 28104","dot":"1179350","ph":"(561) 752-2649","sups":['SOFIA MARTINEZ', 'DAVID WILLIAMS', 'SARAH JONES']},
    {"name":"MARTEN CARGO LOGISTICS LLC LP","addr":"2431 Commerce Dr, NASHVILLE, TN 41359","dot":"360502","ph":"(907) 542-8973","sups":['BARBARA BROWN', 'THOMAS MILLER', 'KAREN GARCIA']},
    {"name":"EASTERN TRANSPORT SERVICES LP","addr":"9168 Main St, HOUSTON, TX 35698","dot":"1200016","ph":"(249) 293-3143","sups":['MARY RAMIREZ', 'LUIS GARCIA', 'LAURA ANDERSON']},
    {"name":"EASTERN TRANSPORT SERVICES CO","addr":"4491 Trucking Ln, EVANSVILLE, IN 63929","dot":"3718590","ph":"(933) 277-8544","sups":['CHARLES THOMAS', 'MARIA PEREZ', 'WILLIAM PEREZ']},
    {"name":"RAMIREZ CARRIERS ENTERPRISES LLC","addr":"9952 Commerce Dr, SPOKANE, WA 87499","dot":"195695","ph":"(694) 647-8354","sups":['JOHN LEE', 'SARAH MOORE', 'SOFIA RAMIREZ']},
    {"name":"LEGACY CROSS COUNTRY TRANSPORT SERVICES LLC","addr":"9729 Airport Rd, KANSAS CITY, MO 91010","dot":"3162929","ph":"(317) 952-1007","sups":['PATRICIA THOMPSON', 'LINDA RAMIREZ', 'LAURA WILSON']},
    {"name":"SMITH LOGISTICS LLC","addr":"1967 Corporate Dr, FRESNO, CA 91052","dot":"3080823","ph":"(751) 757-3793","sups":['DIANA ANDERSON', 'CARLOS ROBINSON', 'KAREN PEREZ']},
    {"name":"EXPRESS LOGISTICS GROUP CO","addr":"5367 Enterprise Way, SHREVEPORT, LA 20302","dot":"1096686","ph":"(247) 399-8797","sups":['CHARLES PEREZ', 'MARY THOMPSON', 'KAREN SMITH']},
    {"name":"NORTHERN SILVER TRANSPORT LLC LP","addr":"3589 Enterprise Way, JACKSON, MS 74008","dot":"3136118","ph":"(938) 408-9133","sups":['CARLOS JOHNSON', 'SARAH JONES', 'MICHAEL RODRIGUEZ']},
    {"name":"USA LINES ENTERPRISES LLC","addr":"2669 Park Ave, LAREDO, TX 26653","dot":"417677","ph":"(476) 706-6131","sups":['SOFIA JOHNSON', 'ANTONIO MARTIN', 'MARIA THOMPSON']},
    {"name":"CROSS COUNTRY CARRIERS LP","addr":"5848 Broad St, COLUMBUS, OH 46443","dot":"701320","ph":"(612) 834-6030","sups":['ROBERT TAYLOR', 'MARIA WILSON', 'BARBARA LEE']},
    {"name":"EXPRESS TRANSPORTATION GROUP LLC","addr":"7992 Cargo Way, CHATTANOOGA, TN 79650","dot":"1895632","ph":"(491) 431-8986","sups":['BARBARA RAMIREZ', 'WILLIAM PEREZ', 'JENNIFER HARRIS']},
    {"name":"ROAD KING CARRIERS CORP","addr":"9218 Trucking Ln, BATON ROUGE, LA 97860","dot":"3751830","ph":"(868) 904-7956","sups":['JOHN GONZALEZ', 'JOHN DAVIS', 'ANTONIO BROWN']},
    {"name":"XPO TRUCKING CO CO","addr":"3986 Eastgate Dr, AKRON, OH 31759","dot":"1350155","ph":"(447) 488-1886","sups":['ANTONIO MARTINEZ', 'MARIA TAYLOR', 'JOSEPH PEREZ']},
    {"name":"THOMPSON HAULING CO","addr":"252 Airport Rd, JACKSON, MS 89375","dot":"1043497","ph":"(286) 918-9352","sups":['PATRICIA WHITE', 'JOHN LEE', 'JENNIFER MARTIN']},
    {"name":"TAYLOR TRUCKING CO ENTERPRISES LLC","addr":"4441 Highway Dr, BIRMINGHAM, AL 47724","dot":"246942","ph":"(562) 222-7687","sups":['MARY MILLER', 'DIANA WILLIAMS', 'JOHN SMITH']},
    {"name":"STAR FREIGHT LOGISTICS LLC CORP","addr":"5375 Corporate Dr, SAN ANTONIO, TX 36865","dot":"541533","ph":"(230) 318-2985","sups":['JESSICA GARCIA', 'JAMES PEREZ', 'DIANA HARRIS']},
    {"name":"HARRIS LINES CO","addr":"1728 Terminal Rd, MCALLEN, TX 13353","dot":"3253005","ph":"(230) 975-8198","sups":['CARLOS MOORE', 'LAURA GONZALEZ', 'CHARLES JONES']},
    {"name":"WESTERN CARRIERS LP","addr":"1325 Distribution Center Rd, COLUMBUS, OH 95394","dot":"1542778","ph":"(345) 939-7463","sups":['JOSEPH RODRIGUEZ', 'JAMES MILLER', 'DIANA MOORE']},
    {"name":"PIONEER EXPRESS HOLDINGS INC","addr":"9593 Freight Way, JOPLIN, MO 88827","dot":"1799719","ph":"(894) 257-4072","sups":['JENNIFER ROBINSON', 'ELIZABETH LOPEZ', 'LINDA WHITE']},
    {"name":"PLAINS UNITED LOGISTICS GROUP HOLDINGS INC","addr":"3164 Highway Dr, SAN ANTONIO, TX 14520","dot":"2536391","ph":"(541) 531-5894","sups":['ELIZABETH TAYLOR', 'JOHN SANCHEZ', 'DAVID HARRIS']},
    {"name":"PREMIER PINNACLE CARRIERS CO","addr":"3300 Trucking Ln, DES MOINES, IA 17556","dot":"2670681","ph":"(563) 720-6130","sups":['BARBARA WILLIAMS', 'CHARLES MILLER', 'MARY THOMPSON']},
    {"name":"AMERICAN IRON TRUCKING CO GROUP LLC","addr":"1777 Terminal Rd, LITTLE ROCK, AR 49775","dot":"795017","ph":"(564) 745-2957","sups":['ELIZABETH GARCIA', 'JOHN MARTIN', 'LUIS PEREZ']},
]

Y_DRIVER=633.3
B1={"employer":569.8,"address":557.2,"sup":544.4,"equip":531.8,"st2":519.2,"dot":468.6,"contact":456.0}
B_OFFSETS=[0.0,139.1,278.3]
X={"driver_name":200,"agency":338,"emp_name":135,"emp_from":456,"addr_val":117,"addr_to":456,
   "sup_val":175,"ph_val":404,"tractor_pct":290,"van_pct":467,"reefer_pct":467,"dot_val":175,
   "yes_val":503,"sig_val":250,"date_val":290}
Y_YES=155.1; Y_SIG=104.4; Y_DATE=86.4

def fmt_my(d): return f"{d.month:02d}/{d.year}"
def today_str():
    d=date.today(); return f"{d.month:02d}/{d.day:02d}/{d.year}"

def build_schedule():
    end3=date.today()-relativedelta(months=random.randint(2,5))
    start3=end3-relativedelta(months=random.randint(9,14))
    end2=start3-relativedelta(months=random.randint(1,2))
    start2=end2-relativedelta(months=random.randint(9,14))
    end1=start2-relativedelta(months=random.randint(1,2))
    start1=end1-relativedelta(months=random.randint(9,14))
    return [{"from":start1,"to":end1},{"from":start2,"to":end2},{"from":start3,"to":end3}]

def generate_data(driver_name, agency=""):
    sched=build_schedule(); picks=_pick_companies(3); emps=[]
    for i,co in enumerate(picks):
        use_reefer=random.random()>0.5
        addr=co["addr"]
        if len(addr)>54: addr=addr[:52]+".."
        emps.append({"c":co,"addr":addr,"from":fmt_my(sched[i]["from"]),"to":fmt_my(sched[i]["to"]),
                     "sup":random.choice(co["sups"]),"van_pct":0 if use_reefer else 100,"reef_pct":100 if use_reefer else 0})
    return {"name":driver_name,"agency":agency,"emps":emps,"today":today_str()}

def make_filled_pdf(driver_name, agency=""):
    data=generate_data(driver_name,agency)
    overlay_buf=BytesIO()
    c=rl_canvas.Canvas(overlay_buf,pagesize=LETTER)
    c.setFillColorRGB(0.10,0.31,0.54)
    def t(text,x,y): c.drawString(x,y,str(text or ""))
    c.setFont("Helvetica",9)
    t(data["name"],X["driver_name"],Y_DRIVER)
    t(data["agency"],X["agency"],Y_DRIVER)
    for i,emp in enumerate(data["emps"]):
        off=B_OFFSETS[i]; co=emp["c"]
        c.setFont("Helvetica",9)
        t(co["name"],X["emp_name"],B1["employer"]-off)
        t(emp["from"],X["emp_from"],B1["employer"]-off)
        t(emp["addr"],X["addr_val"],B1["address"]-off)
        t(emp["to"],X["addr_to"],B1["address"]-off)
        t(emp["sup"],X["sup_val"],B1["sup"]-off)
        t(co["ph"],X["ph_val"],B1["sup"]-off)
        t("100",X["tractor_pct"],B1["equip"]-off)
        if emp["van_pct"]: t("100",X["van_pct"],B1["equip"]-off)
        if emp["reef_pct"]: t("100",X["reefer_pct"],B1["st2"]-off)
        t(co["dot"],X["dot_val"],B1["dot"]-off)
    c.setFont("Helvetica",9); t("yes",X["yes_val"],Y_YES)
    c.setFont("Times-Italic",13); t(data["name"],X["sig_val"],Y_SIG)
    c.setFont("Helvetica",9); t(data["today"],X["date_val"],Y_DATE)
    c.save(); overlay_buf.seek(0)
    blank_reader=pypdf.PdfReader(BLANK_PDF)
    overlay_reader=pypdf.PdfReader(overlay_buf)
    writer=pypdf.PdfWriter()
    page=blank_reader.pages[0]; page.merge_page(overlay_reader.pages[0])
    writer.add_page(page); out=BytesIO(); writer.write(out); out.seek(0)
    return out, data

# Tracks recently used companies to avoid repetition
_recent_companies = []
_AVOID_LAST_N = 50  # avoid repeating any of last 50 used companies

def _pick_companies(n):
    global _recent_companies
    # Build pool excluding recently used
    pool = [c for c in COMPANIES if c["name"] not in _recent_companies]
    if len(pool) < n:
        # Reset if pool too small
        _recent_companies = []
        pool = COMPANIES
    picks = random.sample(pool, n)
    # Track used
    _recent_companies.extend([c["name"] for c in picks])
    if len(_recent_companies) > _AVOID_LAST_N:
        _recent_companies = _recent_companies[-_AVOID_LAST_N:]
    return picks

@app.route("/generate", methods=["POST"])
@login_required
def generate():
    driver=request.form.get("driver_name","").strip()
    agency=request.form.get("agency","").strip()
    if not driver: return jsonify({"error":"Driver name is required"}), 400
    if not os.path.exists(BLANK_PDF): return jsonify({"error":"Exp_form_sample.pdf not found"}), 500
    try:
        pdf_buf, data = make_filled_pdf(driver, agency)
        safe="".join(ch if ch.isalnum() or ch in " _-" else "_" for ch in driver).strip().replace(" ","_")
        filename=f"DriverExperience_{safe}.pdf"
        log_download(current_user.id, driver, agency, filename)
        return send_file(pdf_buf, mimetype="application/pdf", as_attachment=True, download_name=filename)
    except Exception as e:
        return jsonify({"error":str(e)}), 500

# ── Insurance Dashboard ───────────────────────────────────────────────────────

def mock_renewals():
    today = date.today()
    items = [
        {"company":"A and G Express Group LLC", "policy_type":"Auto Liability",    "carrier":"Progressive", "date":(today+timedelta(days=12)).strftime("%m/%d/%Y"), "days":12},
        {"company":"Swift Carriers Inc",         "policy_type":"General Liability", "carrier":"Nationwide",  "date":(today+timedelta(days=21)).strftime("%m/%d/%Y"), "days":21},
        {"company":"BlueSky Transport LLC",      "policy_type":"Cargo",             "carrier":"Travelers",   "date":(today+timedelta(days=28)).strftime("%m/%d/%Y"), "days":28},
        {"company":"Mountain Road Freight",      "policy_type":"Auto Liability",    "carrier":"Progressive", "date":(today+timedelta(days=45)).strftime("%m/%d/%Y"), "days":45},
        {"company":"Lone Star Trucking LLC",     "policy_type":"Physical Damage",   "carrier":"Sentry",      "date":(today+timedelta(days=58)).strftime("%m/%d/%Y"), "days":58},
        {"company":"Eastern Haul Inc",           "policy_type":"Auto Liability",    "carrier":"Canal",       "date":(today+timedelta(days=72)).strftime("%m/%d/%Y"), "days":72},
    ]
    return sorted(items, key=lambda x: x["days"])







@app.route("/dashboard")
@login_required
def dashboard():
    from datetime import datetime as dt
    today = date.today()

    # --- Renewals: real DB ---
    all_r = get_all_renewals(user_id=current_user.id, is_admin=current_user.is_admin)
    for r in all_r:
        try:
            rd = dt.strptime(r["renewal_date"], "%Y-%m-%d").date()
            r["days"] = (rd - today).days
            r["date_fmt"] = rd.strftime("%m/%d/%Y")
        except:
            r["days"] = 999
            r["date_fmt"] = r["renewal_date"]
        if r["days"] <= 30:   r["color"] = "red"
        elif r["days"] <= 60: r["color"] = "yellow"
        else:                  r["color"] = "green"
        r["carrier"] = r.get("carrier", "")
        r["policy_type"] = r.get("policy_type", "")
    all_r_sorted = sorted(all_r, key=lambda x: x["days"])

    stats = {
        "renewals_urgent":  sum(1 for x in all_r if x["days"] <= 30),
        "renewals_upcoming": sum(1 for x in all_r if 30 < x["days"] <= 60),
        "renewals_total":   len(all_r),
    }
    return render_template("dashboard.html",
        renewals=all_r_sorted[:6],
        stats=stats,
        no_renewals=len(all_r)==0
    )

@app.route("/renewals")
@login_required
def renewals():
    from datetime import datetime
    all_r = get_all_renewals(user_id=current_user.id, is_admin=current_user.is_admin)
    today = date.today()
    for r in all_r:
        try:
            rd = datetime.strptime(r["renewal_date"], "%Y-%m-%d").date()
            r["days"] = (rd - today).days
            r["date_fmt"] = rd.strftime("%m/%d/%Y")
        except:
            r["days"] = 999
            r["date_fmt"] = r["renewal_date"]
        if r["days"] <= 30:   r["color"] = "red"
        elif r["days"] <= 60: r["color"] = "yellow"
        else:                  r["color"] = "green"
    stats = {
        "total": len(all_r),
        "urgent": sum(1 for r in all_r if r["days"] <= 30),
        "upcoming": sum(1 for r in all_r if 30 < r["days"] <= 60),
        "ok": sum(1 for r in all_r if r["days"] > 60),
    }
    policy_types = [
        "Auto Liability",
        "General Liability",
        "Cargo",
        "Physical Damage",
        "Full Coverage",
        "Full Coverage without PD",
        "Amazon Package",
        "Occupational Accident",
        "NTL",
        "Workers Comp",
    ]
    carriers = [
        "Progressive",
        "Nationwide",
        "Travelers",
        "Sentry",
        "Canal",
        "Great West",
        "Berkley",
        "Markel",
        "State Auto",
        "National Indemnity",
        "Geico",
        "TIP",
        "Benchmark",
        "Berkshire",
        "Cover Whale",
        "Technologies Insurance",
    ]
    return render_template("renewals.html", renewals=all_r, stats=stats, policy_types=policy_types, carriers=carriers, agents=get_all_agents())

@app.route("/renewals/add", methods=["POST"])
@login_required
def renewals_add():
    company           = request.form.get("company","").strip()
    policy_type       = request.form.get("policy_type","").strip()
    carrier           = request.form.get("carrier","").strip()
    renewal_date      = request.form.get("renewal_date","").strip()
    premium           = request.form.get("premium","").strip()
    notes             = request.form.get("notes","").strip()
    auto_renew        = request.form.get("auto_renew") == "1"
    mc_number         = request.form.get("mc_number","").strip()
    dot_number        = request.form.get("dot_number","").strip()
    owner             = request.form.get("owner","").strip()
    current_insurance = request.form.get("current_insurance","").strip()
    submitted_agents  = ",".join(request.form.getlist("submitted_agents"))
    if not all([company, policy_type, carrier, renewal_date]):
        flash("All required fields must be filled.", "error")
        return redirect(url_for("renewals"))
    create_renewal(company, policy_type, carrier, renewal_date, premium, auto_renew, current_user.id,
                    notes=notes, mc_number=mc_number, dot_number=dot_number, owner=owner,
                    current_insurance=current_insurance, submitted_agents=submitted_agents)
    flash(f"Renewal added for {company}.", "success")
    return redirect(url_for("renewals"))

@app.route("/renewals/edit/<int:rid>", methods=["POST"])
@login_required
def renewals_edit(rid):
    company           = request.form.get("company","").strip()
    policy_type       = request.form.get("policy_type","").strip()
    carrier           = request.form.get("carrier","").strip()
    renewal_date      = request.form.get("renewal_date","").strip()
    premium           = request.form.get("premium","").strip()
    notes             = request.form.get("notes","").strip()
    status            = request.form.get("status","Active").strip()
    auto_renew        = request.form.get("auto_renew") == "1"
    mc_number         = request.form.get("mc_number","").strip()
    dot_number        = request.form.get("dot_number","").strip()
    owner             = request.form.get("owner","").strip()
    current_insurance = request.form.get("current_insurance","").strip()
    submitted_agents  = ",".join(request.form.getlist("submitted_agents"))
    if not all([company, policy_type, carrier, renewal_date]):
        flash("All required fields must be filled.", "error")
        return redirect(url_for("renewals"))
    update_renewal(rid, company, policy_type, carrier, renewal_date, premium, status, auto_renew,
                    notes=notes, mc_number=mc_number, dot_number=dot_number, owner=owner,
                    current_insurance=current_insurance, submitted_agents=submitted_agents)
    flash("Renewal updated.", "success")
    return redirect(url_for("renewals"))

@app.route("/renewals/renew/<int:rid>", methods=["POST"])
@login_required
def renewals_renew(rid):
    r = get_renewal_by_id(rid)
    if not r:
        flash("Renewal not found.", "error")
        return redirect(url_for("renewals"))
    renew_renewal(rid, done_by=current_user.id)
    flash(f"Renewal for {r['company']} pushed to next year.", "success")
    return redirect(url_for("renewals"))

@app.route("/renewals/delete/<int:rid>", methods=["POST"])
@login_required
def renewals_delete(rid):
    r = get_renewal_by_id(rid)
    if r:
        delete_renewal(rid)
        flash(f"Renewal for {r['company']} deleted.", "success")
    return redirect(url_for("renewals"))







@app.route("/guest")
def guest():
    return render_template("guest.html")

@app.route("/guide")
def guide():
    return render_template("guide.html")

# ── Renewals (full) ───────────────────────────────────────────────────────────


@app.route("/renewals/export")
@login_required
def renewals_export():
    import csv, io
    from datetime import datetime as dt
    all_r = get_all_renewals(user_id=current_user.id, is_admin=current_user.is_admin)
    today = date.today()
    output = io.StringIO()
    writer = csv.writer(output)
    writer.writerow(["Company","Policy Type","Carrier","Policy Number","Agent","Renewal Date","Days Left","Premium","Status","Auto-Renew"])
    for r in all_r:
        try:
            rd = dt.strptime(r["renewal_date"], "%Y-%m-%d").date()
            days = (rd - today).days
            date_fmt = rd.strftime("%m/%d/%Y")
        except:
            days = ""
            date_fmt = r["renewal_date"]
        writer.writerow([
            r["company"], r["policy_type"], r["carrier"],
            r.get("policy_number",""), r.get("agent_name",""),
            date_fmt, days, r["premium"], r["status"],
            "Yes" if r["auto_renew"] else "No"
        ])
    output.seek(0)
    from flask import Response
    return Response(
        output.getvalue(),
        mimetype="text/csv",
        headers={"Content-Disposition": f"attachment;filename=renewals_{today.strftime('%Y%m%d')}.csv"}
    )

@app.route("/renewals/email-template/<int:rid>")
@login_required
def renewal_email_template(rid):
    from datetime import datetime as dt
    r = get_renewal_by_id(rid)
    if not r:
        return jsonify({"error": "Not found"}), 404
    try:
        rd = dt.strptime(r["renewal_date"], "%Y-%m-%d").date()
        date_fmt = rd.strftime("%B %d, %Y")
        days = (rd - date.today()).days
    except:
        date_fmt = r["renewal_date"]
        days = "N/A"

    agent_ids = [a for a in (r.get("submitted_agents") or "").split(",") if a]
    all_agents = {str(a["id"]): a for a in get_all_agents()}
    agent_lines = []
    for aid in agent_ids:
        a = all_agents.get(aid)
        if a:
            agent_lines.append(f"{a['name']} <{a['email']}>" if a['email'] else a['name'])
    agents_str = ", ".join(agent_lines) if agent_lines else "N/A"

    subject = f"Policy Renewal Notice - {r['company']} - {date_fmt}"
    body = f"""Dear Team,

We would like to initiate the renewal process for the following policy:

Client:             {r['company']}
MC Number:          {r.get('mc_number') or 'N/A'}
DOT Number:         {r.get('dot_number') or 'N/A'}
Owner:              {r.get('owner') or 'N/A'}
Policy Type:        {r['policy_type']}
Current Insurance:  {r.get('current_insurance') or 'N/A'}
Current Expiry:     {date_fmt}
Days Remaining:     {days}
Annual Premium:     {'$' + r['premium'] if r['premium'] else 'TBD'}
Submitted To:       {agents_str}

Please provide a renewal quote at your earliest convenience so we can ensure continuous coverage for our client.

Thank you,
Yusolve Insurance Operations Team"""
    return jsonify({"subject": subject, "body": body, "company": r["company"]})

@app.route("/renewals/history/<int:rid>")
@login_required
def renewal_history(rid):
    r = get_renewal_by_id(rid)
    if not r:
        flash("Renewal not found.", "error")
        return redirect(url_for("renewals"))
    history = get_renewal_history(rid)
    from datetime import datetime as dt
    today = date.today()
    try:
        rd = dt.strptime(r["renewal_date"], "%Y-%m-%d").date()
        r["days"] = (rd - today).days
        r["date_fmt"] = rd.strftime("%m/%d/%Y")
    except:
        r["days"] = 999
        r["date_fmt"] = r["renewal_date"]
    return render_template("renewal_history.html", renewal=r, history=history)

# ── Payments ──────────────────────────────────────────────────────────────────

def init_payments_db():
    import sqlite3 as _sq
    from auth import DB_PATH as _DB
    con = _sq.connect(_DB)
    con.execute("""
        CREATE TABLE IF NOT EXISTS payments (
            id             INTEGER PRIMARY KEY AUTOINCREMENT,
            company        TEXT NOT NULL,
            policy_number  TEXT NOT NULL DEFAULT '',
            carrier        TEXT NOT NULL DEFAULT '',
            amount         REAL NOT NULL DEFAULT 0,
            due_date       TEXT NOT NULL,
            paid_date      TEXT NOT NULL DEFAULT '',
            status         TEXT NOT NULL DEFAULT 'Pending',
            payment_method TEXT NOT NULL DEFAULT '',
            bank_name      TEXT NOT NULL DEFAULT '',
            reference_num  TEXT NOT NULL DEFAULT '',
            note           TEXT NOT NULL DEFAULT '',
            created_by     INTEGER,
            created_at     TEXT NOT NULL
        )
    """)
    # Add new columns if not exist
    for col in [
        "payment_method TEXT NOT NULL DEFAULT ''",
        "bank_name TEXT NOT NULL DEFAULT ''",
        "reference_num TEXT NOT NULL DEFAULT ''",
    ]:
        try: con.execute(f"ALTER TABLE payments ADD COLUMN {col}")
        except: pass
    con.execute("""
        CREATE TABLE IF NOT EXISTS payment_history (
            id           INTEGER PRIMARY KEY AUTOINCREMENT,
            payment_id   INTEGER NOT NULL,
            action       TEXT NOT NULL,
            old_status   TEXT NOT NULL DEFAULT '',
            new_status   TEXT NOT NULL DEFAULT '',
            note         TEXT NOT NULL DEFAULT '',
            done_by      INTEGER,
            done_by_name TEXT NOT NULL DEFAULT '',
            done_at      TEXT NOT NULL,
            FOREIGN KEY (payment_id) REFERENCES payments(id) ON DELETE CASCADE
        )
    """)
    con.commit(); con.close()

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

def delete_payment(pid):
    import sqlite3 as _sq
    from auth import DB_PATH as _DB
    con = _sq.connect(_DB)
    con.execute("DELETE FROM payments WHERE id=?", (pid,)); con.commit(); con.close()

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

init_payments_db()

@app.route("/payments")
@login_required
def payments():
    from datetime import datetime as dt
    today = date.today()
    all_p = get_all_payments(user_id=current_user.id, is_admin=current_user.is_admin)
    for p in all_p:
        try:
            dd = dt.strptime(p["due_date"], "%Y-%m-%d").date()
            p["due_fmt"] = dd.strftime("%m/%d/%Y")
            p["days_left"] = (dd - today).days
        except:
            p["due_fmt"] = p["due_date"]
            p["days_left"] = 0
        if p["status"] == "Paid":
            p["color"] = "green"
        elif p["days_left"] < 0:
            p["color"] = "red"
            p["status"] = "Overdue"
        elif p["days_left"] <= 7:
            p["color"] = "yellow"
        else:
            p["color"] = "blue"
        if p["paid_date"]:
            try: p["paid_fmt"] = dt.strptime(p["paid_date"], "%Y-%m-%d").strftime("%m/%d/%Y")
            except: p["paid_fmt"] = p["paid_date"]
        else:
            p["paid_fmt"] = ""
    stats = {
        "total": len(all_p),
        "overdue": sum(1 for p in all_p if p["color"] == "red"),
        "due_soon": sum(1 for p in all_p if p["color"] == "yellow"),
        "paid": sum(1 for p in all_p if p["status"] == "Paid"),
        "total_outstanding": sum(p["amount"] for p in all_p if p["status"] != "Paid"),
    }
    carriers = ["First Insurance Funding","Direct Bill","Capital Premium Financing","AFCO","IPFS"]
    return render_template("payments.html", payments=all_p, stats=stats, carriers=carriers, today=today.strftime("%Y-%m-%d"))

@app.route("/payments/add", methods=["POST"])
@login_required
def payments_add():
    company        = request.form.get("company","").strip()
    policy_number  = request.form.get("policy_number","").strip()
    carrier        = request.form.get("carrier","").strip()
    amount         = request.form.get("amount","0").replace(",","").strip()
    due_date       = request.form.get("due_date","").strip()
    payment_method = request.form.get("payment_method","").strip()
    bank_name      = request.form.get("bank_name","").strip()
    reference_num  = request.form.get("reference_num","").strip()
    note           = request.form.get("note","").strip()
    if not all([company, due_date]):
        flash("Company and due date are required.", "error")
        return redirect(url_for("payments"))
    try: float(amount)
    except: amount = "0"
    create_payment(company, policy_number, carrier, amount, due_date, note, current_user.id, payment_method, bank_name, reference_num)
    flash(f"Payment record added for {company}.", "success")
    return redirect(url_for("payments"))

@app.route("/payments/mark-paid/<int:pid>", methods=["POST"])
@login_required
def payments_mark_paid(pid):
    paid_date = request.form.get("paid_date", date.today().strftime("%Y-%m-%d"))
    p = get_payment_by_id(pid)
    if p:
        mark_payment_paid(pid, paid_date, done_by=current_user.id, done_by_name=current_user.full_name)
        flash(f"Payment for {p['company']} marked as paid.", "success")
    return redirect(url_for("payments"))

@app.route("/payments/edit/<int:pid>", methods=["POST"])
@login_required
def payments_edit(pid):
    company        = request.form.get("company","").strip()
    policy_number  = request.form.get("policy_number","").strip()
    carrier        = request.form.get("carrier","").strip()
    amount         = request.form.get("amount","0").replace(",","").strip()
    due_date       = request.form.get("due_date","").strip()
    status         = request.form.get("status","Pending").strip()
    payment_method = request.form.get("payment_method","").strip()
    bank_name      = request.form.get("bank_name","").strip()
    reference_num  = request.form.get("reference_num","").strip()
    note           = request.form.get("note","").strip()
    try: float(amount)
    except: amount = "0"
    update_payment(pid, company, policy_number, carrier, amount, due_date, status, note, payment_method, bank_name, reference_num, done_by=current_user.id, done_by_name=current_user.full_name)
    flash("Payment updated.", "success")
    return redirect(url_for("payments"))

@app.route("/payments/delete/<int:pid>", methods=["POST"])
@login_required
def payments_delete(pid):
    p = get_payment_by_id(pid)
    if p:
        delete_payment(pid)
        flash(f"Payment for {p['company']} deleted.", "success")
    return redirect(url_for("payments"))

@app.route("/payments/export")
@login_required
def payments_export():
    import csv, io
    from datetime import datetime as dt
    all_p = get_all_payments(user_id=current_user.id, is_admin=current_user.is_admin)
    output = io.StringIO()
    writer = csv.writer(output)
    writer.writerow(["Company","Policy #","Carrier","Amount","Due Date","Paid Date","Status","Note"])
    for p in all_p:
        writer.writerow([p["company"], p["policy_number"], p["carrier"],
                         f"${p['amount']:,.2f}", p["due_date"], p["paid_date"],
                         p["status"], p["note"]])
    output.seek(0)
    from flask import Response
    return Response(output.getvalue(), mimetype="text/csv",
        headers={"Content-Disposition": f"attachment;filename=payments_{date.today().strftime('%Y%m%d')}.csv"})

@app.route("/payments/invoice/<int:pid>")
@login_required
def payments_invoice(pid):
    from io import BytesIO
    from reportlab.pdfgen import canvas as rc
    from reportlab.lib.pagesizes import LETTER
    from reportlab.lib import colors
    p = get_payment_by_id(pid)
    if not p:
        flash("Payment not found.", "error"); return redirect(url_for("payments"))
    buf = BytesIO()
    c = rc.Canvas(buf, pagesize=LETTER)
    W, H = LETTER
    # Header
    c.setFillColorRGB(0.075, 0.086, 0.157)
    c.rect(0, H-80, W, 80, fill=1, stroke=0)
    c.setFillColorRGB(0.753, 0.220, 0.169)
    c.rect(0, H-84, W, 4, fill=1, stroke=0)
    c.setFillColorRGB(1,1,1)
    c.setFont("Helvetica-Bold", 22)
    c.drawString(40, H-50, "YUSOLVE")
    c.setFont("Helvetica", 10)
    c.drawString(40, H-65, "Insurance Operations")
    c.setFont("Helvetica-Bold", 28)
    c.setFillColorRGB(0.753, 0.220, 0.169)
    c.drawRightString(W-40, H-52, "INVOICE")
    # Invoice details
    c.setFillColorRGB(0.2, 0.2, 0.2)
    c.setFont("Helvetica", 10)
    y = H - 120
    c.drawString(40, y, f"Invoice Date: {date.today().strftime('%B %d, %Y')}")
    c.drawString(40, y-18, f"Due Date: {p['due_date']}")
    c.drawString(40, y-36, f"Reference: PAY-{pid:05d}")
    # Bill to
    c.setFont("Helvetica-Bold", 11)
    c.setFillColorRGB(0.075, 0.086, 0.157)
    c.drawString(40, y-70, "BILL TO:")
    c.setFont("Helvetica", 11)
    c.setFillColorRGB(0.2, 0.2, 0.2)
    c.drawString(40, y-88, p["company"])
    if p["policy_number"]:
        c.drawString(40, y-106, f"Policy #: {p['policy_number']}")
    if p["carrier"]:
        c.drawString(40, y-124, f"Carrier: {p['carrier']}")
    # Table header
    ty = y - 170
    c.setFillColorRGB(0.075, 0.086, 0.157)
    c.rect(40, ty-4, W-80, 28, fill=1, stroke=0)
    c.setFillColorRGB(1,1,1)
    c.setFont("Helvetica-Bold", 10)
    c.drawString(50, ty+6, "Description")
    c.drawRightString(W-50, ty+6, "Amount")
    # Table row
    c.setFillColorRGB(0.97, 0.97, 0.97)
    c.rect(40, ty-34, W-80, 28, fill=1, stroke=0)
    c.setFillColorRGB(0.2, 0.2, 0.2)
    c.setFont("Helvetica", 10)
    desc = f"Insurance Premium — {p['carrier'] or 'Policy'}"
    if p["policy_number"]: desc += f" (#{p['policy_number']})"
    c.drawString(50, ty-22, desc)
    c.setFont("Helvetica-Bold", 10)
    c.drawRightString(W-50, ty-22, f"${p['amount']:,.2f}")
    # Total
    c.setFillColorRGB(0.075, 0.086, 0.157)
    c.rect(40, ty-72, W-80, 28, fill=1, stroke=0)
    c.setFillColorRGB(1,1,1)
    c.setFont("Helvetica-Bold", 12)
    c.drawString(50, ty-60, "TOTAL DUE")
    c.drawRightString(W-50, ty-60, f"${p['amount']:,.2f}")
    # Status
    c.setFillColorRGB(0.2, 0.2, 0.2)
    c.setFont("Helvetica", 10)
    if p["status"] == "Paid":
        c.setFillColorRGB(0.153, 0.682, 0.376)
        c.setFont("Helvetica-Bold", 14)
        c.drawString(50, ty-110, "✓ PAID")
    if p["note"]:
        c.setFillColorRGB(0.4, 0.4, 0.4)
        c.setFont("Helvetica", 9)
        c.drawString(40, ty-140, f"Note: {p['note']}")
    # Footer
    c.setFillColorRGB(0.6, 0.6, 0.6)
    c.setFont("Helvetica", 8)
    c.drawCentredString(W/2, 40, "Yusolve Insurance Operations — Internal Document")
    c.save()
    buf.seek(0)
    safe = "".join(ch if ch.isalnum() else "_" for ch in p["company"])
    return send_file(buf, mimetype="application/pdf", as_attachment=True,
                     download_name=f"Invoice_{safe}_PAY{pid:05d}.pdf")


@app.route("/mvr")
@login_required
def mvr():
    return redirect(url_for("index"))

@app.route("/payments/history/<int:pid>")
@login_required
def payment_history_view(pid):
    from datetime import datetime as dt
    p = get_payment_by_id(pid)
    if not p:
        flash("Payment not found.", "error")
        return redirect(url_for("payments"))
    history = get_payment_history(pid)
    try:
        dd = dt.strptime(p["due_date"], "%Y-%m-%d").date()
        p["due_fmt"] = dd.strftime("%m/%d/%Y")
        p["days_left"] = (dd - date.today()).days
    except:
        p["due_fmt"] = p["due_date"]
        p["days_left"] = 0
    if p["paid_date"]:
        try: p["paid_fmt"] = dt.strptime(p["paid_date"], "%Y-%m-%d").strftime("%m/%d/%Y")
        except: p["paid_fmt"] = p["paid_date"]
    else:
        p["paid_fmt"] = ""
    return render_template("payment_history.html", payment=p, history=history)

# ── Admin: User Detail & Password Reset ──────────────────────────────────────

@app.route("/admin/user/<int:uid>")
@login_required
@admin_required
def admin_user_detail(uid):
    from datetime import datetime as dt
    target = get_user_by_id(uid)
    if not target:
        flash("User not found.", "error")
        return redirect(url_for("admin_panel"))
    target_user = User(target)
    today = date.today()

    # Renewals for this user
    renewals = get_all_renewals(user_id=uid, is_admin=False)
    for r in renewals:
        try:
            rd = dt.strptime(r["renewal_date"], "%Y-%m-%d").date()
            r["days"] = (rd - today).days
            r["date_fmt"] = rd.strftime("%m/%d/%Y")
        except:
            r["days"] = 999
            r["date_fmt"] = r["renewal_date"]
        if r["days"] <= 30:   r["color"] = "red"
        elif r["days"] <= 60: r["color"] = "yellow"
        else:                  r["color"] = "green"
    renewals = sorted(renewals, key=lambda x: x["days"])

    # Payments for this user
    payments = get_all_payments(user_id=uid, is_admin=False)
    for p in payments:
        try:
            dd = dt.strptime(p["due_date"], "%Y-%m-%d").date()
            p["due_fmt"] = dd.strftime("%m/%d/%Y")
            p["days_left"] = (dd - today).days
        except:
            p["due_fmt"] = p["due_date"]
            p["days_left"] = 0
        if p["status"] == "Paid":
            p["color"] = "green"
        elif p["days_left"] < 0:
            p["color"] = "red"
        elif p["days_left"] <= 7:
            p["color"] = "yellow"
        else:
            p["color"] = "blue"
        if p["paid_date"]:
            try: p["paid_fmt"] = dt.strptime(p["paid_date"], "%Y-%m-%d").strftime("%m/%d/%Y")
            except: p["paid_fmt"] = p["paid_date"]
        else:
            p["paid_fmt"] = ""

    # Download history
    downloads = get_user_downloads(uid)

    stats = {
        "renewals_total": len(renewals),
        "renewals_urgent": sum(1 for r in renewals if r["days"] <= 30),
        "payments_total": len(payments),
        "payments_overdue": sum(1 for p in payments if p["color"]=="red" and p["status"]!="Paid"),
        "outstanding": sum(p["amount"] for p in payments if p["status"] != "Paid"),
        "downloads_total": len(downloads),
    }

    return render_template("admin_user_detail.html",
        target=target_user, renewals=renewals, payments=payments,
        downloads=downloads, stats=stats)

@app.route("/admin/reset-password/<int:uid>", methods=["POST"])
@login_required
@admin_required
def admin_reset_password(uid):
    target = get_user_by_id(uid)
    if not target:
        flash("User not found.", "error")
        return redirect(url_for("admin_panel"))
    if target["auth_provider"] == "google":
        flash("This user signs in with Google — no password to reset.", "error")
        return redirect(url_for("admin_user_detail", uid=uid))

    new_password = request.form.get("new_password", "").strip()
    if len(new_password) < 8:
        flash("Password must be at least 8 characters.", "error")
        return redirect(url_for("admin_user_detail", uid=uid))

    update_user_password(uid, new_password)
    flash(f"Password reset for {target['first_name']} {target['last_name']}. New password: {new_password}", "success")
    return redirect(url_for("admin_user_detail", uid=uid))

@app.route("/admin/generate-password/<int:uid>", methods=["POST"])
@login_required
@admin_required
def admin_generate_password(uid):
    import secrets, string
    target = get_user_by_id(uid)
    if not target:
        flash("User not found.", "error")
        return redirect(url_for("admin_panel"))
    if target["auth_provider"] == "google":
        flash("This user signs in with Google — no password to reset.", "error")
        return redirect(url_for("admin_user_detail", uid=uid))

    chars = string.ascii_letters + string.digits
    new_password = ''.join(secrets.choice(chars) for _ in range(12))
    update_user_password(uid, new_password)
    flash(f"New password generated for {target['first_name']} {target['last_name']}: {new_password}", "success")
    return redirect(url_for("admin_user_detail", uid=uid))

# ── Lease Termination Agreement ─────────────────────────────────────────────

LEASE_TEMPLATE_PATH = os.path.join(BASE_DIR, "lease_template.pdf")
LESSEE_SIG_FOLDER = os.path.join(BASE_DIR, "uploads", "lessee_signatures")
LESSOR_SIG_FOLDER = os.path.join(BASE_DIR, "uploads", "lessor_signatures")
os.makedirs(LESSEE_SIG_FOLDER, exist_ok=True)
os.makedirs(LESSOR_SIG_FOLDER, exist_ok=True)

LEASE_ALLOWED_EXT = {'png', 'jpg', 'jpeg'}

def _lease_allowed_file(filename):
    return '.' in filename and filename.rsplit('.', 1)[1].lower() in LEASE_ALLOWED_EXT

def _lease_random_signature(folder):
    import random as _random
    files = [f for f in os.listdir(folder) if _lease_allowed_file(f)]
    if not files:
        return None
    return os.path.join(folder, _random.choice(files))

def _lease_remove_background(img):
    """Remove white/light background, keep only dark ink strokes. Returns RGBA."""
    from PIL import Image
    import numpy as np
    img = img.convert("RGBA")
    data = np.array(img, dtype=np.float32)
    r, g, b, a = data[:,:,0], data[:,:,1], data[:,:,2], data[:,:,3]
    lightness = (r + g + b) / 3.0
    darkness = 255.0 - lightness
    threshold_low = 40
    threshold_high = 140
    alpha = np.clip((darkness - threshold_low) / (threshold_high - threshold_low), 0, 1)
    alpha = alpha * 255.0
    alpha = np.minimum(alpha, a)
    new_data = np.zeros_like(data)
    new_data[:,:,3] = alpha
    return Image.fromarray(new_data.astype(np.uint8), 'RGBA')

def _lease_pdf_y(top, H=792):
    return H - top

def _lease_create_overlay_pdf(data, lessee_sig_path, lessor_sig_path):
    from PIL import Image
    from reportlab.lib.utils import ImageReader
    packet = BytesIO()
    c = rl_canvas.Canvas(packet, pagesize=LETTER)
    H = 792

    def txt(x, top, text, size=8):
        c.setFont("Helvetica", size)
        c.setFillColorRGB(0, 0, 0)
        c.drawString(x, _lease_pdf_y(top, H), text)

    txt(408, 123, data.get('original_lease_date', ''), size=8)
    txt(135, 146, data.get('lessee_name', ''), size=8)
    txt(290, 146, data.get('lessor_name', ''), size=8)
    txt(92,  233, data.get('unit_no', ''), size=8)
    txt(200, 233, data.get('make', ''), size=8)
    txt(308, 233, data.get('year', ''), size=8)
    txt(380, 233, data.get('vin', ''), size=8)
    txt(185, 282, data.get('lessor_name', ''), size=8)
    txt(92, 309, data.get('lessee_name', ''), size=8)

    termination_date = data.get('termination_date', '')
    txt(340, 337, termination_date, size=8)
    txt(223, 424, termination_date, size=8)

    SIG_W = 130
    SIG_H = 30

    def draw_signature(sig_path, x, sig_line_top):
        if not sig_path or not os.path.exists(sig_path):
            return
        try:
            img = Image.open(sig_path)
            img = _lease_remove_background(img)
            bbox = img.getbbox()
            if bbox:
                img = img.crop(bbox)
            img_reader = ImageReader(img)
            y_bottom = _lease_pdf_y(sig_line_top, H)
            c.drawImage(img_reader, x, y_bottom, width=SIG_W, height=SIG_H,
                        mask='auto', preserveAspectRatio=False)
        except Exception as e:
            print(f"Signature error: {e}")

    draw_signature(lessee_sig_path, 90, 494.6)
    txt(280, 497, data.get('lessee_title', ''), size=8)
    draw_signature(lessor_sig_path, 90, 540.6)
    txt(280, 543, data.get('lessor_title', ''), size=8)

    c.save()
    packet.seek(0)
    return packet


@app.route("/lease-termination")
@login_required
def lease_termination():
    return render_template("lease_termination.html")


@app.route("/lease-termination/generate", methods=["POST"])
@login_required
def lease_termination_generate():
    data = {k: request.form.get(k, '') for k in [
        'original_lease_date', 'lessee_name', 'lessor_name',
        'unit_no', 'make', 'year', 'vin',
        'termination_date',
        'lessee_title', 'lessor_title',
    ]}
    lessee_sig = _lease_random_signature(LESSEE_SIG_FOLDER)
    lessor_sig = _lease_random_signature(LESSOR_SIG_FOLDER)
    overlay_packet = _lease_create_overlay_pdf(data, lessee_sig, lessor_sig)

    template_reader = pypdf.PdfReader(LEASE_TEMPLATE_PATH)
    overlay_reader = pypdf.PdfReader(overlay_packet)
    writer = pypdf.PdfWriter()
    page = template_reader.pages[0]
    page.merge_page(overlay_reader.pages[0])
    writer.add_page(page)

    output = BytesIO()
    writer.write(output)
    output.seek(0)

    try:
        log_download(current_user.id, data.get('lessee_name','') or data.get('lessor_name',''), 'Lease Termination', 'Lease_Termination_Agreement.pdf')
    except Exception:
        pass

    return send_file(output, mimetype='application/pdf', as_attachment=True,
                      download_name='Lease_Termination_Agreement.pdf')


# ── Admin: Signature library management ─────────────────────────────────────

@app.route("/admin/signatures")
@login_required
@admin_required
def admin_signatures():
    lessee_sigs = [f for f in os.listdir(LESSEE_SIG_FOLDER) if _lease_allowed_file(f)]
    lessor_sigs = [f for f in os.listdir(LESSOR_SIG_FOLDER) if _lease_allowed_file(f)]
    return render_template("admin_signatures.html", lessee_sigs=lessee_sigs, lessor_sigs=lessor_sigs)


@app.route("/admin/signatures/upload", methods=["POST"])
@login_required
@admin_required
def admin_signatures_upload():
    from datetime import datetime as _dt
    sig_type = request.form.get('sig_type')
    folder = LESSEE_SIG_FOLDER if sig_type == 'lessee' else LESSOR_SIG_FOLDER if sig_type == 'lessor' else None
    if not folder:
        return jsonify({'error': "Invalid type"}), 400
    if 'signature' not in request.files:
        return jsonify({'error': 'No file'}), 400
    file = request.files['signature']
    if file and _lease_allowed_file(file.filename):
        ext = file.filename.rsplit('.', 1)[1].lower()
        filename = f"sig_{_dt.now().strftime('%Y%m%d%H%M%S%f')}.{ext}"
        file.save(os.path.join(folder, filename))
        return jsonify({'success': True, 'filename': filename})
    return jsonify({'error': 'Only JPG or PNG allowed'}), 400


@app.route("/admin/signatures/delete", methods=["POST"])
@login_required
@admin_required
def admin_signatures_delete():
    sig_type = request.json.get('sig_type')
    filename = request.json.get('filename')
    folder = LESSEE_SIG_FOLDER if sig_type == 'lessee' else LESSOR_SIG_FOLDER if sig_type == 'lessor' else None
    if not folder or not filename:
        return jsonify({'error': 'Invalid'}), 400
    path = os.path.join(folder, filename)
    if os.path.exists(path) and os.path.dirname(os.path.abspath(path)) == os.path.abspath(folder):
        os.remove(path)
        return jsonify({'success': True})
    return jsonify({'error': 'Not found'}), 404


@app.route("/admin/signatures/preview/<sig_type>/<filename>")
@login_required
@admin_required
def admin_signatures_preview(sig_type, filename):
    from flask import send_from_directory
    folder = LESSEE_SIG_FOLDER if sig_type == 'lessee' else LESSOR_SIG_FOLDER
    path = os.path.join(folder, filename)
    if os.path.exists(path) and os.path.dirname(os.path.abspath(path)) == os.path.abspath(folder):
        return send_from_directory(folder, filename)
    return '', 404



# ── Lease Agreement ──────────────────────────────────────────────────────────

LEASE_AGREEMENT_TEMPLATE = os.path.join(BASE_DIR, "lease_agreement_template.pdf")

def _la_create_overlay(data, lessor_sig_path, lessee_sig_path):
    """Create overlay PDF with form data positioned precisely over template fields."""
    from reportlab.lib.pagesizes import A4
    from reportlab.pdfgen import canvas as rl_c
    from datetime import datetime as _dt
    from dateutil.relativedelta import relativedelta
    from PIL import Image
    from reportlab.lib.utils import ImageReader

    W, H = A4  # 595.28 x 841.89 pt

    packet = BytesIO()
    c = rl_c.Canvas(packet, pagesize=A4)

    def put(x, y, text, size=9, bold=False):
        font = "Helvetica-Bold" if bold else "Helvetica"
        c.setFont(font, size)
        c.setFillColorRGB(0, 0, 0)
        c.drawString(x, y, str(text))

    # ── Top section ──
    put(124.6, 702.1, data.get("lessee_name",""), size=9, bold=True)
    put(124.8, 686.8, data.get("lessor_name",""), size=9, bold=True)

    # ── Table row ──
    put(62.4,  622.6, data.get("equip_type",""), size=9)
    put(144.5, 622.6, data.get("year_make",""),  size=9)
    put(236.9, 622.6, data.get("unit_no",""),    size=9)
    put(302.6, 622.6, data.get("vin",""),        size=9)
    put(450.5, 622.6, data.get("plate",""),      size=9)

    # ── Dates ──
    start_str = data.get("start_date","")
    try:
        start_dt = _dt.strptime(start_str, "%Y-%m-%d")
        end_dt   = start_dt + relativedelta(years=1)
        start_fmt = start_dt.strftime("%m/%d/%Y")
        end_fmt   = end_dt.strftime("%m/%d/%Y")
    except:
        start_fmt = start_str
        end_fmt   = ""

    put(152.2, 581.4, start_fmt, size=9, bold=True)
    put(269.5, 581.4, end_fmt,   size=9, bold=True)

    # ── Bottom blocks — centered text ──
    # Lessor center ≈ 185pt, Lessee center ≈ 375pt
    LESSOR_CX = 185.0
    LESSEE_CX = 375.0

    def cput(cx, y, text, size=9, bold=False):
        """Draw centered text at center-x=cx, y=rl_y."""
        font = "Helvetica-Bold" if bold else "Helvetica"
        c.setFont(font, size)
        c.setFillColorRGB(0, 0, 0)
        c.drawCentredString(cx, y, str(text))

    # Lessor block (left, centered at 185pt)
    cput(LESSOR_CX, 197.0, data.get("lessor_name",""),  size=9, bold=True)
    cput(LESSOR_CX, 186.0, data.get("lessor_addr1",""), size=9)
    cput(LESSOR_CX, 175.0, data.get("lessor_addr2",""), size=9)

    # Lessee block (right, centered at 375pt)
    cput(LESSEE_CX, 197.0, data.get("lessee_name",""),  size=9, bold=True)
    cput(LESSEE_CX, 186.0, data.get("lessee_addr1",""), size=9)
    cput(LESSEE_CX, 175.0, data.get("lessee_addr2",""), size=9)

    # ── Signatures ──
    # LEFT (Lessor): x=117.8-253.2pt, ReportLab y_top=207.8
    # RIGHT (Lessee): x=313.4-435.8pt, ReportLab y_top=208.6
    # Signatures — centered under Lessor/Lessee labels
    # Sig area: rl_y top ~208, bottom ~128 (height ~80pt), centered at 185 and 375
    SIG_W = 110
    SIG_H = 55

    def draw_sig(sig_path, cx, y_top):
        """Draw signature centered at cx, top at y_top."""
        if not sig_path or not os.path.exists(sig_path):
            return
        try:
            img = Image.open(sig_path)
            img = _lease_remove_background(img)
            bbox = img.getbbox()
            if bbox:
                img = img.crop(bbox)
            x = cx - SIG_W / 2
            c.drawImage(ImageReader(img), x, y_top - SIG_H, width=SIG_W, height=SIG_H,
                        mask='auto', preserveAspectRatio=True)
        except Exception as e:
            print(f"Sig error: {e}")

    draw_sig(lessor_sig_path, LESSOR_CX, 178.0)
    draw_sig(lessee_sig_path, LESSEE_CX, 178.0)

    c.save()
    packet.seek(0)
    return packet


@app.route("/lease-agreement")
@login_required
def lease_agreement():
    return render_template("lease_agreement.html")


@app.route("/lease-agreement/generate", methods=["POST"])
@login_required
def lease_agreement_generate():
    data = {k: request.form.get(k,"").strip() for k in [
        "lessee_name","lessee_addr1","lessee_addr2",
        "lessor_name","lessor_addr1","lessor_addr2",
        "equip_type","year_make","unit_no","vin","plate",
        "start_date",
    ]}

    lessor_sig = _lease_random_signature(LESSOR_SIG_FOLDER)
    lessee_sig = _lease_random_signature(LESSEE_SIG_FOLDER)

    overlay  = _la_create_overlay(data, lessor_sig, lessee_sig)
    template = pypdf.PdfReader(LEASE_AGREEMENT_TEMPLATE)
    overlay_r = pypdf.PdfReader(overlay)
    writer   = pypdf.PdfWriter()
    page     = template.pages[0]
    page.merge_page(overlay_r.pages[0])
    writer.add_page(page)

    output = BytesIO()
    writer.write(output)
    output.seek(0)

    try:
        unit = data.get("unit_no","")
        log_download(current_user.id, f"Unit {unit}", "Lease Agreement", "Lease_Agreement.pdf")
    except:
        pass

    return send_file(output, mimetype="application/pdf",
                     as_attachment=True, download_name="Lease_Agreement.pdf")




# ── Admin: Manage Agents ──────────────────────────────────────────────────────

@app.route("/admin/agents")
@login_required
@admin_required
def admin_agents():
    agents = get_all_agents()
    return render_template("admin_agents.html", agents=agents)

@app.route("/admin/agents/add", methods=["POST"])
@login_required
@admin_required
def admin_agents_add():
    name = request.form.get("name","").strip()
    email = request.form.get("email","").strip()
    if not name:
        flash("Agent name is required.", "error")
        return redirect(url_for("admin_agents"))
    create_agent(name, email)
    flash(f"Agent '{name}' added.", "success")
    return redirect(url_for("admin_agents"))

@app.route("/admin/agents/delete/<int:aid>", methods=["POST"])
@login_required
@admin_required
def admin_agents_delete(aid):
    delete_agent(aid)
    flash("Agent removed.", "success")
    return redirect(url_for("admin_agents"))


# ── Renewal Quotes (market + price, filled in later) ─────────────────────────

@app.route("/renewals/quotes/<int:rid>")
@login_required
def renewal_quotes_view(rid):
    r = get_renewal_by_id(rid)
    if not r:
        return jsonify({"error": "Not found"}), 404
    quotes = get_quotes_for_renewal(rid)
    return jsonify({"quotes": quotes, "company": r["company"]})

@app.route("/renewals/quotes/<int:rid>/add", methods=["POST"])
@login_required
def renewal_quotes_add(rid):
    market = request.form.get("market","").strip()
    price  = request.form.get("price","").strip()
    if not market:
        return jsonify({"error": "Market is required"}), 400
    qid = add_quote(rid, market, price)
    return jsonify({"success": True, "id": qid, "market": market, "price": price})

@app.route("/renewals/quotes/delete/<int:qid>", methods=["POST"])
@login_required
def renewal_quotes_delete(qid):
    delete_quote(qid)
    return jsonify({"success": True})





if __name__ == "__main__":
    print("=" * 55)
    print("  Yusolve Insurance Operations Portal")
    print("  Dashboard: http://localhost:5000/dashboard")
    print("=" * 55)
    port = int(os.environ.get("PORT", 5000))
    app.run(debug=False, host="0.0.0.0", port=port)
