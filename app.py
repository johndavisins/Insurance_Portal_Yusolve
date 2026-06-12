import os, random
from datetime import date, timedelta
from io import BytesIO
from dateutil.relativedelta import relativedelta
from flask import Flask, render_template, request, send_file, jsonify, redirect, url_for, flash
from flask_login import login_user, logout_user, login_required, current_user
import pypdf
from reportlab.pdfgen import canvas as rl_canvas
from reportlab.lib.pagesizes import LETTER
from authlib.integrations.flask_client import OAuth
from auth import (init_db, login_manager, admin_required, get_user_by_email,
                  get_user_by_google_id, get_all_users, create_user, update_user_role,
                  delete_user, verify_password, User, get_user_by_id,
                  update_user_profile, update_user_password, log_download,
                  get_user_downloads, delete_download_history,
                  init_renewals_db, get_all_renewals, get_renewal_by_id,
                  create_renewal, update_renewal, delete_renewal, renew_renewal,
                  get_renewal_history, get_all_renewal_history,
                  get_all_payments, get_payment_by_id, create_payment,
                  mark_payment_paid, get_payment_history, update_payment, delete_payment)

app = Flask(__name__)
app.secret_key = os.environ.get("SECRET_KEY", "yusolve-dev-secret-2025")
login_manager.init_app(app)
login_manager.login_view = "login"

GOOGLE_CLIENT_ID     = os.environ.get("GOOGLE_CLIENT_ID", "948077622554-j82mqt0t7abqngiv82jhoup35t9nc1hq.apps.googleusercontent.com")
GOOGLE_CLIENT_SECRET = os.environ.get("GOOGLE_CLIENT_SECRET", "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")
oauth = OAuth(app)
google = oauth.register(
    name="google", client_id=GOOGLE_CLIENT_ID, client_secret=GOOGLE_CLIENT_SECRET,
    server_metadata_url="https://accounts.google.com/.well-known/openid-configuration",
    client_kwargs={"scope": "openid email profile"},
)

BLANK_PDF = os.path.join(os.path.dirname(os.path.abspath(__file__)), "Exp_form_sample.pdf")
init_db()
init_renewals_db()

# ── Auth Routes ───────────────────────────────────────────────────────────────

@app.route("/login", methods=["GET","POST"])
def login():
    if current_user.is_authenticated:
        return redirect(url_for("index"))
    if request.method == "POST":
        email    = request.form.get("email","").strip().lower()
        password = request.form.get("password","")
        data = get_user_by_email(email)
        if not data or data["auth_provider"] != "email" or not verify_password(data["password_hash"], password):
            flash("Invalid email or password.", "error")
            return render_template("login.html")
        login_user(User(data), remember=True)
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

@app.route("/login/google")
def login_google():
    if not GOOGLE_CLIENT_ID:
        flash("Google login not configured.", "error"); return redirect(url_for("login"))
    return google.authorize_redirect(url_for("google_callback", _external=True))

@app.route("/login/google/callback")
def google_callback():
    try:
        token    = google.authorize_access_token()
        print("TOKEN:", token)
        userinfo = token.get("userinfo") or google.userinfo()
        print("USERINFO:", userinfo)
    except Exception as e:
        import traceback; traceback.print_exc()
        flash(f"Google login failed: {e}", "error"); return redirect(url_for("login"))

    try:
        google_id  = str(userinfo.get("sub",""))
        email      = userinfo.get("email","").lower()
        parts      = userinfo.get("name","").split(" ",1)
        first_name = parts[0]; last_name = parts[1] if len(parts)>1 else ""
        print(f"google_id={google_id} email={email} name={first_name} {last_name}")

        data = get_user_by_google_id(google_id)
        if not data:
            data = get_user_by_email(email)
            if data and not data.get("google_id"):
                import sqlite3
                from auth import DB_PATH
                con = sqlite3.connect(DB_PATH)
                con.execute("UPDATE users SET google_id=?,auth_provider='google' WHERE id=?", (google_id, data["id"]))
                con.commit(); con.close()
                data = get_user_by_id(data["id"])
            elif not data:
                data = create_user(first_name, last_name, email, auth_provider="google", google_id=google_id)

        print("USER DATA:", data)
        if not data:
            flash("Could not create account.", "error"); return redirect(url_for("login"))
        login_user(User(data), remember=True)
        return redirect(url_for("index"))
    except Exception as e:
        import traceback; traceback.print_exc()
        flash(f"Google login error: {e}", "error"); return redirect(url_for("login"))

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
    users = [User(u) for u in get_all_users()]
    return render_template("admin.html", users=users)

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
    {"name":"SPI TRANSPORTATION INC","addr":"679 S BEST BUSINESS AVE STE 101, KUNA, ID 83634","dot":"1885407","ph":"(208) 922-5771","sups":["CARL JONES","JOSE GARCIA","JOSHUA THOMPSON"]},
    {"name":"SWIFT TRANSPORTATION CO LLC","addr":"2200 S 75TH AVE, PHOENIX, AZ 85043","dot":"2230677","ph":"(602) 269-9700","sups":["STEVEN TAYLOR","JOSEPH MILLER","JOSHUA THOMAS"]},
    {"name":"WERNER ENTERPRISES INC","addr":"14507 FRONTIER RD, OMAHA, NE 68138","dot":"793920","ph":"(402) 895-6640","sups":["RUTH WHITE","DEBORAH HARRIS","ARTHUR HARRIS"]},
    {"name":"J B HUNT TRANSPORT INC","addr":"615 J B HUNT CORPORATE DR, LOWELL, AR 72745","dot":"80782","ph":"(479) 820-0000","sups":["DOUGLAS JONES","MELISSA JOHNSON","ROGER JONES"]},
    {"name":"PRIME INC","addr":"2740 N MAYFAIR AVE, SPRINGFIELD, MO 65803","dot":"357653","ph":"(417) 521-3000","sups":["MATTHEW ALLEN","JENNIFER YOUNG","RICHARD ANDERSON"]},
    {"name":"SCHNEIDER NATIONAL CARRIERS INC","addr":"3101 S PACKERLAND DR, GREEN BAY, WI 54313","dot":"126797","ph":"(920) 592-2000","sups":["CHRISTOPHER JONES","AMANDA JOHNSON","DEBRA JACKSON"]},
    {"name":"KNIGHT TRANSPORTATION INC","addr":"2002 W WAHALLA LN, PHOENIX, AZ 85027","dot":"281221","ph":"(602) 269-2000","sups":["KAREN ALLEN","MARY ANDERSON","DENNIS GARCIA"]},
    {"name":"OLD DOMINION FREIGHT LINE INC","addr":"500 OLD DOMINION WAY, THOMASVILLE, NC 27360","dot":"264184","ph":"(336) 889-5000","sups":["HELEN WILSON","JENNIFER HARRIS","RONALD DAVIS"]},
    {"name":"HEARTLAND EXPRESS INC","addr":"901 N KANSAS AVE, NORTH LIBERTY, IA 52317","dot":"325570","ph":"(319) 626-3600","sups":["KIMBERLY GARCIA","SCOTT WILSON","MARGARET TAYLOR"]},
    {"name":"USA TRUCK INC","addr":"3200 INDUSTRIAL PARK RD, VAN BUREN, AR 72956","dot":"50604","ph":"(479) 471-2500","sups":["DONALD YOUNG","JOSEPH JACKSON","ERIC ALLEN"]},
    {"name":"XPO LOGISTICS FREIGHT INC","addr":"5 AMERICAN LN, GREENWICH, CT 06831","dot":"1234518","ph":"(855) 976-4636","sups":["PETER SMITH","CAROL DAVIS","HENRY WHITE"]},
    {"name":"ROEHL TRANSPORT INC","addr":"1916 EASTERN AVE, MARSHFIELD, WI 54449","dot":"1234512","ph":"(715) 387-3742","sups":["RAYMOND MILLER","DONNA MILLER","PATRICIA GARCIA"]},
    {"name":"ESTES EXPRESS LINES","addr":"3901 WEST BROAD ST, RICHMOND, VA 23230","dot":"020960","ph":"(804) 353-1900","sups":["GARY TAYLOR","AMY THOMAS","RUTH JACKSON"]},
    {"name":"MARTEN TRANSPORT LTD","addr":"129 MARTEN ST, MONDOVI, WI 54755","dot":"281937","ph":"(715) 926-4216","sups":["SCOTT JONES","JOSEPH THOMAS","BRIAN WHITE"]},
    {"name":"COVENANT TRANSPORT INC","addr":"400 BIRMINGHAM HWY, CHATTANOOGA, TN 37419","dot":"338366","ph":"(423) 821-1212","sups":["DONNA MARTIN","MELISSA KING","SANDRA GARCIA"]},
    {"name":"RUSH EXPRESS INC","addr":"4553 FREIGHT PKW, BOISE, ID 83201","dot":"1193645","ph":"(208) 223-1752","sups":["MELISSA THOMPSON","LINDA DAVIS","JASON TAYLOR"]},
    {"name":"DIAMOND CARRIER CORP","addr":"1169 HIGHWAY BLVD, ST PAUL, MN 55101","dot":"300809","ph":"(763) 256-9861","sups":["EDWARD WHITE","RUTH ANDERSON","RONALD DAVIS"]},
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
    sched=build_schedule(); picks=random.sample(COMPANIES,3); emps=[]
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
    return render_template("renewals.html", renewals=all_r, stats=stats, policy_types=policy_types, carriers=carriers)

@app.route("/renewals/add", methods=["POST"])
@login_required
def renewals_add():
    company       = request.form.get("company","").strip()
    policy_type   = request.form.get("policy_type","").strip()
    carrier       = request.form.get("carrier","").strip()
    renewal_date  = request.form.get("renewal_date","").strip()
    premium       = request.form.get("premium","").strip()
    policy_number = request.form.get("policy_number","").strip()
    agent_name    = request.form.get("agent_name","").strip()
    notes         = request.form.get("notes","").strip()
    auto_renew    = request.form.get("auto_renew") == "1"
    if not all([company, policy_type, carrier, renewal_date]):
        flash("All required fields must be filled.", "error")
        return redirect(url_for("renewals"))
    create_renewal(company, policy_type, carrier, renewal_date, premium, auto_renew, current_user.id, policy_number, agent_name, notes)
    flash(f"Renewal added for {company}.", "success")
    return redirect(url_for("renewals"))

@app.route("/renewals/edit/<int:rid>", methods=["POST"])
@login_required
def renewals_edit(rid):
    company       = request.form.get("company","").strip()
    policy_type   = request.form.get("policy_type","").strip()
    carrier       = request.form.get("carrier","").strip()
    renewal_date  = request.form.get("renewal_date","").strip()
    premium       = request.form.get("premium","").strip()
    policy_number = request.form.get("policy_number","").strip()
    agent_name    = request.form.get("agent_name","").strip()
    notes         = request.form.get("notes","").strip()
    status        = request.form.get("status","Active").strip()
    auto_renew    = request.form.get("auto_renew") == "1"
    if not all([company, policy_type, carrier, renewal_date]):
        flash("All required fields must be filled.", "error")
        return redirect(url_for("renewals"))
    update_renewal(rid, company, policy_type, carrier, renewal_date, premium, status, auto_renew, policy_number, agent_name, notes)
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
    subject = f"Policy Renewal Notice – {r['company']} – {date_fmt}"
    body = f"""Dear {r['carrier']} Team,

We would like to initiate the renewal process for the following policy:

Client:         {r['company']}
Policy Type:    {r['policy_type']}
Policy Number:  {r.get('policy_number') or 'N/A'}
Current Expiry: {date_fmt}
Days Remaining: {days}
Annual Premium: {'$' + r['premium'] if r['premium'] else 'TBD'}
Agent:          {r.get('agent_name') or 'N/A'}

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
    carriers = ["Progressive","Nationwide","Travelers","Sentry","Canal","Great West","Berkley","Markel","State Auto","National Indemnity","Geico","TIP","Benchmark","Berkshire","Cover Whale","Technologies Insurance"]
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

if __name__ == "__main__":
    print("=" * 55)
    print("  Yusolve Insurance Operations Portal")
    print("  Dashboard: http://localhost:5000/dashboard")
    print("=" * 55)
    app.run(debug=False, port=5000)