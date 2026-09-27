from flask import (
    Flask,
    render_template,
    request,
    redirect,
    url_for,
    session,
    send_file,
    jsonify
)
from werkzeug.security import generate_password_hash, check_password_hash

import pandas as pd
from datetime import datetime
import json
import os
import sqlite3

import scoring
import io
from fpdf import FPDF

# ============================================================
# APP
# ============================================================

app = Flask(__name__)

app.secret_key = "sizokuthola_secret_key"

# ============================================================
# LOAD DATA
# ============================================================

DATA_PATH = os.path.join(
    "data",
    "SIZOKUTHOLA_Final_Dataset.csv"
)

activities = pd.read_csv(DATA_PATH, low_memory=False)

# ============================================================
# USERS
# ============================================================

# NOTE: admin/analyst accounts used to be a fixed dict with exactly one
# of each. They're now a real database (see the "STAFF ACCOUNTS" section
# below) so multiple named administrators and analysts can each have
# their own login -- which is what makes it possible to know exactly
# *who* added an employee or *who* verified an alert, not just "admin"
# or "analyst" generically.

# ============================================================
# ALERT VERIFICATION STORE (SQLite)
# ============================================================
# This is what makes the critical-alert siren "sticky": once an
# analyst signs off on a specific batch of critical alerts, that
# sign-off is written here and survives page refreshes, new
# logins, and server restarts. It also doubles as the audit log
# the user asked to keep "for later use".

VERIFICATIONS_DB = os.path.join("data", "verifications.db")


def get_db_connection():

    conn = sqlite3.connect(VERIFICATIONS_DB)

    conn.row_factory = sqlite3.Row

    return conn


def init_verifications_db():

    os.makedirs("data", exist_ok=True)

    conn = get_db_connection()

    conn.execute(
        """
        CREATE TABLE IF NOT EXISTS verifications (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            signature TEXT NOT NULL,
            analyst_name TEXT NOT NULL,
            badge TEXT NOT NULL,
            notes TEXT,
            critical_count INTEGER,
            high_count INTEGER,
            verified_by TEXT,
            verified_at TEXT NOT NULL
        )
        """
    )

    conn.commit()

    conn.close()


init_verifications_db()


# ============================================================
# STAFF ACCOUNTS (Administrators and Security Analysts)
# ============================================================
# Real, individually-named accounts -- not one shared "admin" login and
# one shared "analyst" login. This is what lets every action (adding an
# employee, verifying an alert) be tied to a specific person.

DEFAULT_STAFF_PASSWORD = "Welcome@123"


def init_staff_table():

    conn = get_db_connection()

    conn.execute(
        """
        CREATE TABLE IF NOT EXISTS staff (
            username TEXT PRIMARY KEY,
            password_hash TEXT NOT NULL,
            display_name TEXT NOT NULL,
            role TEXT NOT NULL
        )
        """
    )

    conn.execute(
        """
        CREATE TABLE IF NOT EXISTS staff_audit_log (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            username TEXT NOT NULL,
            role TEXT NOT NULL,
            action TEXT NOT NULL,
            target TEXT,
            performed_at TEXT NOT NULL
        )
        """
    )

    conn.commit()

    conn.close()


init_staff_table()


def seed_default_staff():
    """
    Preserves the original admin/analyst logins as real accounts on
    first run, so nothing breaks for anyone already using them --
    but from here on, more named accounts can be added on top.
    """

    conn = get_db_connection()

    existing = {row["username"] for row in conn.execute("SELECT username FROM staff").fetchall()}

    defaults = [
        ("admin", "admin123", "Default Administrator", "Administrator"),
        ("analyst", "analyst123", "Default Security Analyst", "Security Analyst"),
    ]

    for username, password, display_name, role in defaults:

        if username in existing:
            continue

        conn.execute(
            "INSERT INTO staff (username, password_hash, display_name, role) VALUES (?, ?, ?, ?)",
            (username, generate_password_hash(password), display_name, role),
        )

    conn.commit()

    conn.close()


seed_default_staff()


def get_staff(username):

    conn = get_db_connection()

    row = conn.execute("SELECT * FROM staff WHERE username = ?", (username,)).fetchone()

    conn.close()

    return dict(row) if row else None


def get_all_staff():

    conn = get_db_connection()

    rows = conn.execute("SELECT username, display_name, role FROM staff ORDER BY role, username").fetchall()

    conn.close()

    return [dict(r) for r in rows]


def add_staff(username, password, display_name, role):

    username = username.strip()

    if not username or not password or not display_name:
        return False, "Username, password, and display name are all required."

    if role not in ("Administrator", "Security Analyst"):
        return False, "Role must be Administrator or Security Analyst."

    if get_staff(username):
        return False, f"An account with username '{username}' already exists."

    conn = get_db_connection()

    conn.execute(
        "INSERT INTO staff (username, password_hash, display_name, role) VALUES (?, ?, ?, ?)",
        (username, generate_password_hash(password), display_name, role),
    )

    conn.commit()

    conn.close()

    return True, f"{role} account '{username}' created."


def delete_staff(username):

    conn = get_db_connection()

    conn.execute("DELETE FROM staff WHERE username = ?", (username,))

    conn.commit()

    conn.close()


def log_staff_action(username, role, action, target=""):
    """
    A durable 'who did what' record -- every time an admin adds or
    removes an employee, or an analyst verifies an alert, it's written
    here so there's a real audit trail to look back on.
    """

    conn = get_db_connection()

    conn.execute(
        "INSERT INTO staff_audit_log (username, role, action, target, performed_at) VALUES (?, ?, ?, ?, ?)",
        (username, role, action, target, datetime.now().strftime("%d %B %Y %I:%M %p")),
    )

    conn.commit()

    conn.close()


def get_staff_audit_log(limit=50):

    conn = get_db_connection()

    rows = conn.execute(
        "SELECT * FROM staff_audit_log ORDER BY id DESC LIMIT ?", (limit,)
    ).fetchall()

    conn.close()

    return [dict(r) for r in rows]


def build_alert_signature(critical_ids, high_ids, critical_count, high_count):
    """
    A fingerprint of exactly which Critical AND High alerts are
    currently flagged. If the underlying set of flagged accounts
    changes at all -- even if the counts happen to stay the same --
    this changes too, and the siren is armed again even if an older
    batch was already verified.
    """

    c_ids = ",".join(str(i) for i in critical_ids)
    h_ids = ",".join(str(i) for i in high_ids)

    return f"{critical_count}:{high_count}:{c_ids}:{h_ids}"


def is_signature_verified(signature):

    conn = get_db_connection()

    row = conn.execute(
        "SELECT id FROM verifications WHERE signature = ? ORDER BY id DESC LIMIT 1",
        (signature,)
    ).fetchone()

    conn.close()

    return row is not None


def save_verification(signature, name, badge, notes, critical_count, high_count, verified_by):

    conn = get_db_connection()

    conn.execute(
        """
        INSERT INTO verifications
            (signature, analyst_name, badge, notes, critical_count, high_count, verified_by, verified_at)
        VALUES (?, ?, ?, ?, ?, ?, ?, ?)
        """,
        (
            signature,
            name,
            badge,
            notes,
            critical_count,
            high_count,
            verified_by,
            datetime.now().strftime("%d %B %Y %I:%M %p"),
        )
    )

    conn.commit()

    conn.close()


def get_recent_verifications(limit=10):

    conn = get_db_connection()

    rows = conn.execute(
        "SELECT * FROM verifications ORDER BY id DESC LIMIT ?",
        (limit,)
    ).fetchall()

    conn.close()

    return [dict(r) for r in rows]


# ============================================================
# LIVE EMPLOYEE MONITORING (accounts + captured activity)
# ============================================================
# `employees` holds real login credentials, one row per user_id already
# present in the historical dataset (role/department/province/subject
# come straight from that dataset, so permissions line up automatically).
#
# `activity_log` holds every live action an employee performs, already
# scored by scoring.py using your trained models -- this is the "live"
# counterpart to SIZOKUTHOLA_Final_Dataset.csv.

DEFAULT_EMPLOYEE_PASSWORD = "Employee@123"


def init_employee_tables():

    conn = get_db_connection()

    conn.execute(
        """
        CREATE TABLE IF NOT EXISTS employees (
            user_id TEXT PRIMARY KEY,
            password_hash TEXT NOT NULL,
            role TEXT,
            department TEXT,
            province TEXT,
            subject_permission TEXT,
            work_email TEXT
        )
        """
    )

    conn.execute(
        """
        CREATE TABLE IF NOT EXISTS activity_log (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            timestamp TEXT,
            user_id TEXT,
            location TEXT,
            action TEXT,
            filename TEXT,
            url TEXT,
            to_email TEXT,
            from_email TEXT,
            role TEXT,
            department TEXT,
            province TEXT,
            subject_permission TEXT,
            hour INTEGER,
            day INTEGER,
            month INTEGER,
            weekday TEXT,
            after_hours INTEGER,
            weekend INTEGER,
            exam_period INTEGER,
            records_accessed INTEGER,
            days_to_exam INTEGER,
            work_email TEXT,
            accessed_subject TEXT,
            allowed_exam_access INTEGER,
            handled_exam_paper INTEGER,
            unauthorised_exam_access INTEGER,
            risk_score INTEGER,
            risk_level TEXT,
            iso_prediction INTEGER,
            cluster INTEGER,
            kmeans_prediction INTEGER,
            behaviour_score INTEGER,
            threat_level TEXT,
            final_prediction INTEGER,
            alert_message TEXT,
            recommendation TEXT,
            risk_reason TEXT
        )
        """
    )

    conn.commit()

    conn.close()


init_employee_tables()


def seed_employees_from_dataset():
    """
    One account per user_id already in the historical dataset, with
    role/department/province/subject_permission pre-filled. Safe to call
    on every startup -- existing accounts (and any password changes) are
    left untouched.
    """

    conn = get_db_connection()

    existing = {
        row["user_id"]
        for row in conn.execute("SELECT user_id FROM employees").fetchall()
    }

    unique_employees = activities.drop_duplicates(subset="user_id", keep="first")

    default_hash = generate_password_hash(DEFAULT_EMPLOYEE_PASSWORD)

    inserted = 0

    for _, row in unique_employees.iterrows():

        user_id = row["user_id"]

        if user_id in existing:
            continue

        work_email = row.get("work_email") or f"{str(user_id).lower()}@dbe.gov.za"

        conn.execute(
            """
            INSERT INTO employees
                (user_id, password_hash, role, department, province, subject_permission, work_email)
            VALUES (?, ?, ?, ?, ?, ?, ?)
            """,
            (
                user_id,
                default_hash,
                row["role"],
                row["department"],
                row["province"],
                row["subject_permission"],
                work_email,
            )
        )

        inserted += 1

    conn.commit()

    conn.close()

    return inserted


seeded_count = seed_employees_from_dataset()

if seeded_count:
    print(f"Seeded {seeded_count} employee account(s). Default password: {DEFAULT_EMPLOYEE_PASSWORD}")


def get_employee(user_id):

    conn = get_db_connection()

    row = conn.execute(
        "SELECT * FROM employees WHERE user_id = ?",
        (user_id,)
    ).fetchone()

    conn.close()

    return dict(row) if row else None


def get_all_employees():
    """
    Every registered employee account, regardless of whether they've
    logged any live activity yet. This is the real employee database --
    the CSV is only ever used once, at first startup, to give you a
    starting roster; everything from here on can be managed directly.
    """

    conn = get_db_connection()

    rows = conn.execute(
        "SELECT user_id, role, department, province, subject_permission, work_email "
        "FROM employees ORDER BY user_id"
    ).fetchall()

    conn.close()

    return [dict(r) for r in rows]


def add_employee(user_id, password, role, department, province, subject_permission):
    """
    Create a new employee account by hand -- no CSV involved. Returns
    (success, message).
    """

    user_id = user_id.strip()

    if not user_id or not password:
        return False, "User ID and password are required."

    if get_employee(user_id):
        return False, f"An employee with user ID '{user_id}' already exists."

    work_email = f"{user_id.lower()}@dbe.gov.za"

    conn = get_db_connection()

    conn.execute(
        """
        INSERT INTO employees
            (user_id, password_hash, role, department, province, subject_permission, work_email)
        VALUES (?, ?, ?, ?, ?, ?, ?)
        """,
        (
            user_id,
            generate_password_hash(password),
            role,
            department,
            province,
            subject_permission,
            work_email,
        )
    )

    conn.commit()

    conn.close()

    return True, f"Employee '{user_id}' created. They can log in with the password you set."


def delete_employee(user_id):

    conn = get_db_connection()

    conn.execute("DELETE FROM employees WHERE user_id = ?", (user_id,))

    conn.commit()

    conn.close()


def insert_activity(scored):

    conn = get_db_connection()

    conn.execute(
        """
        INSERT INTO activity_log (
            timestamp, user_id, location, action, filename, url, to_email, from_email,
            role, department, province, subject_permission, hour, day, month, weekday,
            after_hours, weekend, exam_period, records_accessed, days_to_exam, work_email,
            accessed_subject, allowed_exam_access, handled_exam_paper, unauthorised_exam_access,
            risk_score, risk_level, iso_prediction, cluster, kmeans_prediction,
            behaviour_score, threat_level, final_prediction, alert_message, recommendation, risk_reason
        ) VALUES (?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?)
        """,
        (
            scored["timestamp"].isoformat(),
            scored["user_id"],
            scored["location"],
            scored["action"],
            scored["filename"],
            scored["url"],
            scored["to_email"],
            scored["from_email"],
            scored["role"],
            scored["department"],
            scored["province"],
            scored["subject_permission"],
            scored["hour"],
            scored["day"],
            scored["month"],
            scored["weekday"],
            scored["after_hours"],
            scored["weekend"],
            scored["exam_period"],
            scored["records_accessed"],
            scored["days_to_exam"],
            scored["work_email"],
            scored["accessed_subject"],
            int(scored["allowed_exam_access"]),
            int(scored["handled_exam_paper"]),
            int(scored["unauthorised_exam_access"]),
            scored["risk_score"],
            scored["risk_level"],
            scored["iso_prediction"],
            scored["cluster"],
            scored["kmeans_prediction"],
            scored["behaviour_score"],
            scored["threat_level"],
            scored["final_prediction"],
            scored["alert_message"],
            scored["recommendation"],
            scored["risk_reason"],
        )
    )

    conn.commit()

    conn.close()


def get_recent_activity_for_user(user_id, limit=15):
    """
    An employee's own activity history -- their real historical records
    from the training dataset plus anything they've done live this
    session. Live rows sort first so a fresh action is always visible
    without scrolling past years of history.
    """

    df = get_combined_activity_df()

    if df.empty:
        return []

    user_df = df[df["user_id"] == user_id].copy()

    if user_df.empty:
        return []

    user_df["is_live"] = user_df["source"] == "Live"

    user_df = user_df.sort_values(
        by=["is_live", "timestamp"], ascending=[False, False]
    )

    return user_df.head(limit).to_dict("records")


def capture_event(user_id, action, **kwargs):
    """
    The one function everything else calls to record a live action:
    scores it with the trained models (scoring.py) and writes it to
    activity_log. kwargs can include filename, url, to_email, from_email,
    accessed_subject, records_accessed, location.
    """

    employee = get_employee(user_id)

    if not employee:
        return None

    event = {
        "action": action,
        "location": kwargs.get("location") or "Workstation",
        "filename": kwargs.get("filename", ""),
        "url": kwargs.get("url", ""),
        "to_email": kwargs.get("to_email", ""),
        "from_email": kwargs.get("from_email", ""),
        "accessed_subject": kwargs.get("accessed_subject") or employee.get("subject_permission", ""),
        "records_accessed": kwargs.get("records_accessed", 1),
        "timestamp": datetime.now(),
    }

    scored = scoring.score_event(event, employee)

    insert_activity(scored)

    return scored


# Load the trained models + fit encoders from the historical dataset.
# Must run after `activities` is loaded and before any live event is scored.
scoring.init_scoring(activities, models_dir="models")


# ============================================================
# COMBINED DASHBOARD DATA (historical CSV + live activity_log)
# ============================================================
# The historical CSV gives the system a fully populated baseline to
# demonstrate with -- 50,000 records, real charts, real alerts. Every
# row coming from live employee activity is tagged source="Live" so it's
# visually distinguishable everywhere, and combined counts update the
# instant someone logs in and does something.

COMMON_ACTIVITY_COLS = [
    "timestamp", "user_id", "location", "action", "filename", "url",
    "to_email", "from_email", "role", "department", "province",
    "subject_permission", "hour", "day", "month", "weekday",
    "after_hours", "weekend", "exam_period", "records_accessed",
    "days_to_exam", "work_email", "accessed_subject",
    "allowed_exam_access", "handled_exam_paper",
    "unauthorised_exam_access", "risk_score", "risk_level",
    "iso_prediction", "cluster", "kmeans_prediction", "behaviour_score",
    "threat_level", "final_prediction", "alert_message",
    "recommendation", "risk_reason",
]


def get_activity_log_df():

    conn = sqlite3.connect(VERIFICATIONS_DB)

    df = pd.read_sql_query("SELECT * FROM activity_log", conn)

    conn.close()

    return df


def get_live_session_status():
    """
    Runs the same threat-level logic used everywhere else, but scoped to
    activity_log only (i.e. only what's actually happened live this
    session) -- this is the "is what just happened High or Critical"
    verdict, distinct from the lifetime totals baked into the historical
    dataset.
    """

    df = get_activity_log_df()

    if df.empty:
        return {
            "level": "IDLE",
            "critical": 0, "high": 0, "medium": 0, "low": 0,
            "total": 0, "last_action": None,
        }

    critical = len(df[df["threat_level"] == "Critical"])
    high = len(df[df["threat_level"] == "High"])
    medium = len(df[df["threat_level"] == "Medium"])
    low = len(df[df["threat_level"] == "Low"])

    if critical > 0:
        level = "CRITICAL"
    elif high > 0:
        level = "HIGH"
    elif medium > 0:
        level = "ELEVATED"
    else:
        level = "NORMAL"

    last_row = df.sort_values("timestamp", ascending=False).iloc[0]

    return {
        "level": level,
        "critical": critical, "high": high, "medium": medium, "low": low,
        "total": len(df),
        "last_action": {
            "user_id": last_row["user_id"],
            "action": last_row["action"],
            "threat_level": last_row["threat_level"],
        },
    }


def get_combined_activity_df():
    """
    Historical CSV rows + live activity_log rows, unioned on the columns
    they share, each tagged with where it came from.
    """

    hist = activities.copy()
    hist["source"] = "Historical"
    hist = hist[COMMON_ACTIVITY_COLS + ["source"]]

    live = get_activity_log_df()

    if live.empty:
        return hist

    live = live.copy()
    live["source"] = "Live"
    live = live[COMMON_ACTIVITY_COLS + ["source"]]

    return pd.concat([hist, live], ignore_index=True)


def get_employee_provinces():

    conn = get_db_connection()

    rows = conn.execute(
        "SELECT DISTINCT province FROM employees WHERE province IS NOT NULL ORDER BY province"
    ).fetchall()

    conn.close()

    return [row["province"] for row in rows]


def get_unauthorised_access_evidence(limit=50):
    """
    Every event (historical or live) where the employee accessed a
    subject they were not permitted for -- the "logged in, accessed
    Mathematics P1, was only permitted Geography" evidence trail. Live
    rows are tagged so they stand out from the historical baseline.
    """

    df = get_combined_activity_df()

    if df.empty:
        return []

    mismatched = df[
        df["subject_permission"].notna()
        & (df["subject_permission"] != "")
        & df["accessed_subject"].notna()
        & (df["accessed_subject"] != df["subject_permission"])
    ]

    mismatched = mismatched.sort_values(
        by=["source", "timestamp"], ascending=[False, False]
    ).head(limit)

    return mismatched.to_dict("records")


def live_dashboard_data():

    df = get_combined_activity_df()

    data = {}

    if df.empty:

        data["employees"] = 0
        data["records"] = 0
        data["alerts"] = 0
        data["high"] = 0
        data["critical"] = 0
        data["live_records"] = 0
        data["threat_labels"] = ["Low", "Medium", "High", "Critical"]
        data["threat_values"] = [0, 0, 0, 0]
        data["province_labels"] = []
        data["province_values"] = []
        data["department_labels"] = []
        data["department_values"] = []
        data["role_labels"] = []
        data["role_values"] = []
        data["top_employees"] = []
        data["recent_alerts"] = []

        return data

    # ----------------------------
    # KPIs
    # ----------------------------

    data["employees"] = df["user_id"].nunique()

    data["records"] = len(df)

    data["live_records"] = int((df["source"] == "Live").sum())

    data["alerts"] = int(df["final_prediction"].sum())

    data["high"] = len(df[df["threat_level"] == "High"])

    data["critical"] = len(df[df["threat_level"] == "Critical"])

    # ----------------------------
    # Threat Levels
    # ----------------------------

    threat = (
        df["threat_level"]
        .value_counts()
        .reindex(["Low", "Medium", "High", "Critical"], fill_value=0)
    )

    data["threat_labels"] = list(threat.index)

    data["threat_values"] = [int(x) for x in threat.values]

    # ----------------------------
    # Province
    # ----------------------------

    province = (
        df.groupby("province")["final_prediction"]
        .sum()
        .sort_values(ascending=False)
    )

    data["province_labels"] = list(province.index)

    data["province_values"] = [int(x) for x in province.values]

    # ----------------------------
    # Department
    # ----------------------------

    department = (
        df.groupby("department")["final_prediction"]
        .sum()
        .sort_values(ascending=False)
    )

    data["department_labels"] = list(department.index)

    data["department_values"] = [int(x) for x in department.values]

    # ----------------------------
    # Role
    # ----------------------------

    role = (
        df.groupby("role")["final_prediction"]
        .sum()
        .sort_values(ascending=False)
    )

    data["role_labels"] = list(role.index)

    data["role_values"] = [int(x) for x in role.values]

    # ----------------------------
    # Top Employees (by behaviour_score; live rows sort first so a
    # fresh demo login is immediately visible without hunting for it)
    # ----------------------------

    data["top_employees"] = (
        df.sort_values(by=["source", "behaviour_score"], ascending=[False, False])
        .head(10)
        .to_dict("records")
    )

    # ----------------------------
    # Recent Alerts (same live-first ordering)
    # ----------------------------

    data["recent_alerts"] = (
        df[df["final_prediction"] == 1]
        .sort_values(by=["source", "behaviour_score"], ascending=[False, False])
        .head(15)
        .to_dict("records")
    )

    return data
# ============================================================
# LOGIN
# ============================================================

@app.route("/")
def login():
    """
    The landing page: just a choice between the two portals. No auth
    logic lives here -- that's what /staff/login and /employee/login
    are for.
    """

    if "user" in session:

        if session.get("role") == "Employee":
            return redirect(url_for("employee_portal"))

        if session.get("role") == "Security Analyst":
            return redirect(url_for("alerts"))

        return redirect(url_for("dashboard"))

    return render_template("login.html")


@app.route("/staff/login", methods=["GET", "POST"])
def staff_login():

    if request.method == "POST":

        username = request.form["username"]
        password = request.form["password"]

        staff = get_staff(username)

        if staff and check_password_hash(staff["password_hash"], password):

            session["user"] = username
            session["role"] = staff["role"]
            session["display_name"] = staff["display_name"]

            if session["role"] == "Security Analyst":
                return redirect(url_for("alerts"))

            return redirect(url_for("dashboard"))

        error = (
            "Incorrect password for that staff account."
            if staff
            else "No staff account found with that username."
        )

        return render_template("staff_login.html", error=error)

    return render_template("staff_login.html")


@app.route("/employee/login", methods=["GET", "POST"])
def employee_login():

    if request.method == "POST":

        username = request.form["username"]
        password = request.form["password"]

        employee = get_employee(username)

        if employee and check_password_hash(employee["password_hash"], password):

            session["user"] = username
            session["role"] = "Employee"

            # every login is itself a captured, scored event -- the
            # dashboards and alerts reflect this within the same
            # request, not on some delayed batch job.
            capture_event(username, "Logon")

            return redirect(url_for("employee_portal"))

        error = (
            "Incorrect password for that employee account."
            if employee
            else "No employee account found with that User ID. Ask an administrator to add one on the Employees page."
        )

        return render_template("employee_login.html", error=error)

    return render_template("employee_login.html")


# ============================================================
# LOGOUT
# ============================================================

@app.route("/logout")
def logout():

    session.clear()

    return redirect(url_for("login"))


# ============================================================
# EMPLOYEE PORTAL (employees only -- no monitoring data visible here)
# ============================================================

# What each role is actually supposed to be doing, and whether they're
# authorised to handle exam papers -- matches ROLE_ALLOWED_EXAM_ACCESS in
# scoring.py exactly, so the guidance shown here is never out of sync
# with what actually gets flagged as unauthorised.
ROLE_GUIDANCE = {
    "Chief Examination Officer": {
        "allowed": True,
        "summary": "You're in charge of the exam process for your subject.",
        "may": "Look at, check, and handle the exam papers for your subject.",
        "may_not": "Touch exam papers for any subject that isn't yours.",
    },
    "Provincial Examination Coordinator": {
        "allowed": True,
        "summary": "You coordinate exams across your province for your subject.",
        "may": "Access and handle exam papers for your subject.",
        "may_not": "Look at exam papers outside your subject or your province.",
    },
    "Senior Examination Officer": {
        "allowed": True,
        "summary": "You run exam admin for your subject.",
        "may": "Access and handle exam papers for your subject.",
        "may_not": "Access exam papers for any other subject.",
    },
    "Printing Technician": {
        "allowed": True,
        "summary": "You print the exam papers.",
        "may": "Access and print exam papers for your subject only.",
        "may_not": "Print, copy, or open exam papers for any subject that isn't yours.",
    },
    "Data Capturer": {
        "allowed": False,
        "summary": "You capture results and other admin records.",
        "may": "Access results and admin files for your department.",
        "may_not": "Touch exam papers at all -- that's not part of your job.",
    },
    "ICT Administrator": {
        "allowed": False,
        "summary": "You keep the IT systems running.",
        "may": "Access system logs, accounts, and infrastructure settings.",
        "may_not": "Open exam paper content -- you're tech support, not exam staff.",
    },
    "Warehouse Officer": {
        "allowed": False,
        "summary": "You manage storage and delivery of exam materials.",
        "may": "Track and log the movement of sealed exam materials.",
        "may_not": "Open or look inside any exam paper.",
    },
}

# ============================================================
# DAILY TASKS -- a rotating, role-specific checklist
# ============================================================
# Each role has a pool of legitimate duties. Every employee gets a
# random subset each day (seeded by user_id + date, so it's stable for
# the whole day but different tomorrow). Tasks that reference a subject
# always use the employee's own subject_permission -- these represent
# normal, authorised work; anything outside this list is exactly the
# kind of deviation the rest of the system is built to flag.

import random

DAILY_TASK_COUNT = 3

ROLE_TASK_POOLS = {
    "Senior Examination Officer": [
        {"action": "Logon", "description": "Log in and start your day."},
        {"action": "File Access", "use_subject": True, "description": "Check the {subject} paper for mistakes."},
        {"action": "File Copy", "use_subject": True, "description": "Get the {subject} paper ready to print."},
        {"action": "Email", "description": "Send your supervisor a quick update."},
        {"action": "Download", "use_subject": True, "description": "Download the {subject} moderation report."},
    ],
    "Chief Examination Officer": [
        {"action": "Logon", "description": "Log in and start your day."},
        {"action": "File Access", "use_subject": True, "description": "Give the final {subject} paper a last check before sign-off."},
        {"action": "Email", "description": "Let the provincial coordinators know it's signed off."},
        {"action": "Download", "use_subject": True, "description": "Download the {subject} moderation checklist."},
    ],
    "Provincial Examination Coordinator": [
        {"action": "Logon", "description": "Log in and start your day."},
        {"action": "File Access", "use_subject": True, "description": "See how {subject} papers are moving in your province."},
        {"action": "Email", "description": "Send the district offices the delivery schedule."},
        {"action": "Web Browsing", "description": "Check the logistics portal for updates."},
    ],
    "Printing Technician": [
        {"action": "Logon", "description": "Log in and start your day."},
        {"action": "File Copy", "use_subject": True, "description": "Copy the {subject} paper to the print server."},
        {"action": "USB Insert", "description": "Plug in the secure USB drive for the print batch."},
        {"action": "Download", "use_subject": True, "description": "Download the {subject} print instructions."},
    ],
    "Data Capturer": [
        {"action": "Logon", "description": "Log in and start your day."},
        {"action": "File Access", "description": "Open today's results sheet."},
        {"action": "Download", "description": "Download the latest results template."},
        {"action": "Email", "description": "Let your supervisor know you're done capturing."},
    ],
    "ICT Administrator": [
        {"action": "Logon", "description": "Log in and start your day."},
        {"action": "Web Browsing", "description": "Check the system dashboard for any outages."},
        {"action": "File Access", "description": "Look over today's access logs."},
        {"action": "Email", "description": "Flag anything odd to IT support."},
    ],
    "Warehouse Officer": [
        {"action": "Logon", "description": "Log in and start your day."},
        {"action": "USB Device", "description": "Scan in today's stock movements."},
        {"action": "Web Browsing", "description": "Check the delivery schedule for today."},
        {"action": "Email", "description": "Confirm to the coordinator that stock arrived."},
    ],
}


def get_daily_tasks(employee):
    """
    A stable-for-today, random-tomorrow subset of this employee's role's
    task pool. Same employee, same day, same tasks -- refreshing the
    page doesn't reshuffle them.
    """

    role = employee.get("role", "")

    pool = ROLE_TASK_POOLS.get(role) or ROLE_TASK_POOLS["Data Capturer"]

    today_str = datetime.now().strftime("%Y-%m-%d")

    rng = random.Random(f"{employee.get('user_id','')}-{today_str}")

    count = min(DAILY_TASK_COUNT, len(pool))

    chosen = rng.sample(pool, count)

    subject = employee.get("subject_permission", "")

    tasks = []

    for i, t in enumerate(chosen):

        tasks.append({
            "id": i + 1,
            "action": t["action"],
            "accessed_subject": subject if t.get("use_subject") else None,
            "description": t["description"].replace("{subject}", subject),
        })

    return tasks


def get_tasks_with_completion(employee):
    """Today's tasks, each tagged with whether it's already been done."""

    tasks = get_daily_tasks(employee)

    conn = get_db_connection()

    today_str = datetime.now().strftime("%Y-%m-%d")

    rows = conn.execute(
        "SELECT action, accessed_subject FROM activity_log WHERE user_id = ? AND timestamp LIKE ?",
        (employee["user_id"], today_str + "%")
    ).fetchall()

    conn.close()

    done_pairs = {(r["action"], r["accessed_subject"] or "") for r in rows}

    done_actions = {r["action"] for r in rows}

    result = []

    for t in tasks:

        if t["accessed_subject"]:
            is_done = (t["action"], t["accessed_subject"]) in done_pairs
        else:
            is_done = t["action"] in done_actions

        result.append({**t, "done": is_done})

    return result

# Fixed option lists for the portal's action form, taken from the
# dataset's own vocabulary so every value matches what the models expect.
EMPLOYEE_ACTIONS = [
    "Logon", "File Access", "Download", "File Copy",
    "Email", "USB Device", "USB Insert", "Web Browsing",
]

SUBJECT_OPTIONS = [
    "Accounting", "Business Studies", "English FAL", "English HL",
    "Geography", "Life Sciences", "Mathematical Literacy",
    "Mathematics", "Physical Sciences",
]

# Fixed vocabulary for the "add employee" form -- matches the roles,
# departments, and provinces the trained models actually recognise.
ROLE_OPTIONS = [
    "Chief Examination Officer", "Data Capturer", "ICT Administrator",
    "Printing Technician", "Provincial Examination Coordinator",
    "Senior Examination Officer", "Warehouse Officer",
]

DEPARTMENT_OPTIONS = [
    "Examination Administration", "Logistics", "Provincial Office",
    "Question Paper Development", "Results Processing", "Secure Printing",
]

PROVINCE_OPTIONS = [
    "Eastern Cape", "Free State", "Gauteng", "KwaZulu-Natal", "Limpopo",
    "Mpumalanga", "North West", "Northern Cape", "Western Cape",
]


@app.route("/employee/portal")
def employee_portal():

    if "user" not in session:
        return redirect(url_for("login"))

    if session.get("role") != "Employee":
        return redirect(url_for("dashboard"))

    employee = get_employee(session["user"])

    # If this session has been open since before today (browser sessions
    # don't expire on their own), there may be no Logon captured for
    # *today* specifically -- which left "Log in and start your day"
    # stuck as incomplete even though the person is clearly here and
    # working. Whenever the portal loads and today has no Logon on
    # record yet, capture one now -- this is what "still logged in,
    # working today" actually means in a real system.
    if employee:

        today_str = datetime.now().strftime("%Y-%m-%d")

        conn = get_db_connection()

        already_logged_today = conn.execute(
            "SELECT 1 FROM activity_log WHERE user_id = ? AND action = 'Logon' AND timestamp LIKE ? LIMIT 1",
            (session["user"], today_str + "%")
        ).fetchone()

        conn.close()

        if not already_logged_today:
            capture_event(session["user"], "Logon")

    recent_activity = get_recent_activity_for_user(session["user"], limit=15)

    guidance = ROLE_GUIDANCE.get(employee["role"] if employee else "", {
        "allowed": False,
        "summary": "No guidance is on file for this role yet.",
        "may": "Contact your administrator to confirm your responsibilities.",
        "may_not": "Access exam papers until your role is confirmed.",
    })

    daily_tasks = get_tasks_with_completion(employee) if employee else []

    return render_template(

        "employee_portal.html",

        user=session["user"],

        role=session["role"],

        employee=employee,

        recent_activity=recent_activity,

        action_options=EMPLOYEE_ACTIONS,

        subject_options=SUBJECT_OPTIONS,

        guidance=guidance,

        daily_tasks=daily_tasks,

        current_time=datetime.now().strftime("%d %B %Y %I:%M %p"),

    )


@app.route("/employee/action", methods=["POST"])
def employee_action():

    if "user" not in session:
        return redirect(url_for("login"))

    if session.get("role") != "Employee":
        return redirect(url_for("dashboard"))

    action = request.form.get("action", "File Access")
    filename = request.form.get("filename", "")
    accessed_subject = request.form.get("accessed_subject", "")

    # A Data Capturer's "capture a result" form sends student_id + mark
    # instead of a raw filename -- turn that into a real, readable
    # filename so it shows up honestly in their activity history and in
    # the admin's view of what they actually did.
    student_id = request.form.get("student_id", "").strip()
    mark = request.form.get("mark", "").strip()

    if student_id and mark:
        subject_slug = (accessed_subject or "Results").replace(" ", "")
        filename = f"Result_{subject_slug}_{student_id}_{mark}pct.xlsx"

    capture_event(

        session["user"],

        action,

        filename=filename,

        url=request.form.get("url", ""),

        to_email=request.form.get("to_email", ""),

        from_email=request.form.get("from_email", ""),

        accessed_subject=accessed_subject,

        records_accessed=request.form.get("records_accessed", 1),

        location=request.form.get("location", "Workstation"),

    )

    # File-based actions trigger an actual file download in the browser,
    # not just a log entry. Every action -- file-based or not -- also
    # carries a "done=1" confirmation so the portal can show a clear
    # on-screen banner ("Email sent", "Sent to printing queue and
    # downloaded"). Without this, an action that worked correctly still
    # *feels* broken because nothing visibly changes on screen.
    FILE_ACTIONS = {"Download", "File Copy", "File Access", "USB Insert"}

    if action in FILE_ACTIONS and filename:

        return redirect(url_for(
            "employee_portal",
            download="1",
            done="1",
            filename=filename,
            subject=accessed_subject,
            file_action=action,
        ))

    return redirect(url_for(
        "employee_portal",
        done="1",
        file_action=action,
    ))


def generate_demo_document(subject, filename, employee, action):
    """
    A real, downloadable PDF -- clearly labelled as simulated so it's
    never mistaken for an actual DBE exam paper. This is what makes
    "Download" / "File Copy" / "File Access" feel real in a demo instead
    of just writing a log row.
    """

    pdf = FPDF()
    pdf.add_page()

    pdf.set_font("Helvetica", "B", 15)
    pdf.set_text_color(180, 30, 30)
    pdf.cell(0, 10, "SIMULATED DOCUMENT - NOT A REAL EXAM PAPER", ln=True, align="C")

    pdf.set_font("Helvetica", "", 10)
    pdf.set_text_color(90, 90, 90)
    pdf.multi_cell(
        0, 6,
        "This file was generated automatically by SIZOKUTHOLA for demonstration purposes only. "
        "It contains no real Department of Basic Education examination content.",
        align="C",
    )
    pdf.ln(6)

    pdf.set_draw_color(200, 200, 200)
    pdf.line(15, pdf.get_y(), 195, pdf.get_y())
    pdf.ln(8)

    pdf.set_text_color(20, 20, 20)
    pdf.set_font("Helvetica", "B", 13)
    pdf.cell(0, 8, f"Subject: {subject or 'N/A'}", ln=True)

    pdf.set_font("Helvetica", "", 11)
    pdf.cell(0, 7, f"Requested filename: {filename}", ln=True)
    pdf.cell(0, 7, f"Action: {action}", ln=True)
    pdf.cell(0, 7, f"Accessed by: {employee.get('user_id','')} ({employee.get('role','')})", ln=True)
    pdf.cell(0, 7, f"Department: {employee.get('department','')}", ln=True)
    pdf.cell(0, 7, f"Timestamp: {datetime.now().strftime('%d %B %Y %I:%M %p')}", ln=True)

    pdf.ln(8)
    pdf.set_font("Helvetica", "B", 12)
    pdf.cell(0, 8, "SECTION A (sample)", ln=True)

    pdf.set_font("Helvetica", "", 11)
    pdf.multi_cell(
        0, 7,
        "Question 1\n"
        f"This is placeholder question content standing in for a real {subject or 'exam'} paper. "
        "It exists only to demonstrate that a file was genuinely accessed and downloaded through the "
        "SIZOKUTHOLA insider threat monitoring system, and to show the resulting activity being scored "
        "and logged in real time.\n\n"
        "Question 2\n"
        "(placeholder) ......................................................",
    )

    pdf.ln(10)
    pdf.set_font("Helvetica", "I", 9)
    pdf.set_text_color(150, 150, 150)
    pdf.cell(0, 6, "SIZOKUTHOLA -- Department of Basic Education -- Simulated content, demo build.", ln=True, align="C")

    return bytes(pdf.output())


@app.route("/employee/get-file")
def employee_get_file():

    if "user" not in session or session.get("role") != "Employee":
        return redirect(url_for("login"))

    employee = get_employee(session["user"])

    filename = request.args.get("filename") or "document.pdf"
    subject = request.args.get("subject") or employee.get("subject_permission", "")
    action = request.args.get("file_action") or "Download"

    pdf_bytes = generate_demo_document(subject, filename, employee, action)

    download_name = filename if filename.lower().endswith(".pdf") else f"{filename}.pdf"

    return send_file(
        io.BytesIO(pdf_bytes),
        as_attachment=True,
        download_name=download_name,
        mimetype="application/pdf",
    )


# ============================================================
# DASHBOARD
# ============================================================

@app.route("/dashboard")
def dashboard():

    if "user" not in session:

        return redirect(url_for("login"))

    if session.get("role") == "Employee":

        return redirect(url_for("employee_portal"))

    if session.get("role") == "Security Analyst":

        return redirect(url_for("alerts"))

    data = live_dashboard_data()

    live_session = get_live_session_status()

    return render_template(

        "dashboard.html",

        user=session["user"],

        role=session["role"],

        live_session=live_session,

        employees=data["employees"],

        records=data["records"],

        alerts=data["alerts"],

        high=data["high"],

        critical=data["critical"],

        current_time=datetime.now().strftime("%d %B %Y %I:%M %p"),

        top_employees=data["top_employees"],

        recent_alerts=data["recent_alerts"],

        threat_labels=json.dumps(
            data["threat_labels"]
        ),

        threat_values=json.dumps(
            data["threat_values"]
        ),

        province_labels=json.dumps(
            data["province_labels"]
        ),

        province_values=json.dumps(
            data["province_values"]
        ),

        department_labels=json.dumps(
            data["department_labels"]
        ),

        department_values=json.dumps(
            data["department_values"]
        ),

        role_labels=json.dumps(
            data["role_labels"]
        ),

        role_values=json.dumps(
            data["role_values"]
        ),

        live_records=data.get("live_records", 0),

    )


# ============================================================
# EMPLOYEES
# ============================================================

@app.route("/employees")
def employees():

    if "user" not in session:
        return redirect(url_for("login"))

    if session.get("role") == "Employee":
        return redirect(url_for("employee_portal"))

    if session.get("role") == "Security Analyst":
        return redirect(url_for("alerts"))

    df = get_combined_activity_df()

    # ===========================
    # Employee Statistics
    # ===========================

    if df.empty:
        total_employees = 0
        high_risk = 0
        critical = 0
        average_behaviour = 0
        employee_table = []
    else:
        total_employees = df["user_id"].nunique()
        high_risk = len(df[df["threat_level"] == "High"])
        critical = len(df[df["threat_level"] == "Critical"])
        average_behaviour = round(df["behaviour_score"].mean(), 1)

        # ===========================
        # Employee Table
        # ===========================

        display_df = df.copy()

        display_df["is_live"] = display_df["source"] == "Live"

        employee_table = (

            display_df[
                [
                    "user_id",
                    "role",
                    "province",
                    "behaviour_score",
                    "threat_level",
                    "recommendation",
                    "source",
                    "is_live",
                ]
            ]

            .sort_values(["is_live", "behaviour_score"], ascending=[False, False])

            .head(100)

            .to_dict("records")

        )

    # ===========================
    # Province Filter
    # ===========================
    # Pulled from registered employee accounts, not activity_log, so the
    # filter always offers every real province even before anyone from
    # it has logged any activity yet.

    provinces = get_employee_provinces()

    all_employees = get_all_employees()

    return render_template(

        "employees.html",

        user=session["user"],

        role=session["role"],

        employees=total_employees,

        high_risk=high_risk,

        critical=critical,

        average_behaviour=average_behaviour,

        provinces=provinces,

        employee_table=employee_table,

        all_employees=all_employees,

        role_options=ROLE_OPTIONS,

        department_options=DEPARTMENT_OPTIONS,

        province_options=PROVINCE_OPTIONS,

        subject_options=SUBJECT_OPTIONS,

        add_success=request.args.get("added"),

        add_message=request.args.get("msg"),

    )


@app.route("/employees/add", methods=["POST"])
def employees_add():

    if "user" not in session:
        return redirect(url_for("login"))

    if session.get("role") == "Employee":
        return redirect(url_for("employee_portal"))

    if session.get("role") == "Security Analyst":
        return redirect(url_for("alerts"))

    success, message = add_employee(

        user_id=request.form.get("user_id", ""),

        password=request.form.get("password", ""),

        role=request.form.get("role", ""),

        department=request.form.get("department", ""),

        province=request.form.get("province", ""),

        subject_permission=request.form.get("subject_permission", ""),

    )

    if success:

        log_staff_action(
            username=session["user"],
            role=session["role"],
            action="Added employee",
            target=request.form.get("user_id", ""),
        )

    return redirect(url_for("employees", added=("1" if success else "0"), msg=message))


@app.route("/employees/delete", methods=["POST"])
def employees_delete():

    if "user" not in session:
        return redirect(url_for("login"))

    if session.get("role") == "Employee":
        return redirect(url_for("employee_portal"))

    if session.get("role") == "Security Analyst":
        return redirect(url_for("alerts"))

    user_id = request.form.get("user_id", "")

    if user_id:
        delete_employee(user_id)

        log_staff_action(
            username=session["user"],
            role=session["role"],
            action="Removed employee",
            target=user_id,
        )

    return redirect(url_for("employees"))


@app.route("/employees/<user_id>")
def employee_detail(user_id):
    """
    The per-employee record book -- who they are, what they're supposed
    to be doing, and a real audit trail of everything they've actually
    done (historical training data + live), same spirit as the
    verification log but for one person at a time.
    """

    if "user" not in session:
        return redirect(url_for("login"))

    if session.get("role") == "Employee":
        return redirect(url_for("employee_portal"))

    employee = get_employee(user_id)

    if not employee:
        return redirect(url_for("employees"))

    df = get_combined_activity_df()

    user_df = df[df["user_id"] == user_id].copy() if not df.empty else df

    if user_df.empty:

        activity_history = []

        stats = {
            "total_actions": 0,
            "avg_behaviour": 0,
            "highest_threat": "Low",
            "live_count": 0,
            "unauthorised_count": 0,
        }

    else:

        user_df["is_live"] = user_df["source"] == "Live"

        user_df = user_df.sort_values(by=["is_live", "timestamp"], ascending=[False, False])

        activity_history = user_df.head(200).to_dict("records")

        threat_rank = {"Low": 0, "Medium": 1, "High": 2, "Critical": 3}

        highest_threat = max(user_df["threat_level"], key=lambda t: threat_rank.get(t, 0))

        mismatched = (
            user_df["subject_permission"].notna()
            & (user_df["subject_permission"] != "")
            & user_df["accessed_subject"].notna()
            & (user_df["accessed_subject"] != user_df["subject_permission"])
        )

        stats = {
            "total_actions": len(user_df),
            "avg_behaviour": round(user_df["behaviour_score"].mean(), 1),
            "highest_threat": highest_threat,
            "live_count": int((user_df["source"] == "Live").sum()),
            "unauthorised_count": int(mismatched.sum()),
        }

    guidance = ROLE_GUIDANCE.get(employee["role"], {
        "allowed": False,
        "summary": "No guidance is on file for this role yet.",
        "may": "Not specified.",
        "may_not": "Not specified.",
    })

    daily_tasks = get_tasks_with_completion(employee)

    return render_template(

        "employee_detail.html",

        user=session["user"],

        role=session["role"],

        employee=employee,

        activity_history=activity_history,

        total_activity_count=stats["total_actions"],

        stats=stats,

        guidance=guidance,

        daily_tasks=daily_tasks,

    )

# ============================================================
# ALERTS
# ============================================================

@app.route("/alerts")
def alerts():

    if "user" not in session:
        return redirect(url_for("login"))

    if session.get("role") == "Employee":
        return redirect(url_for("employee_portal"))

    df = get_combined_activity_df()

    # -----------------------------
    # Alert Table
    # -----------------------------
    # Full set drives the verification signature (so nothing critical is
    # silently excluded from what an analyst is asked to sign off on);
    # the display is capped so the page stays usable with 50k+ historical
    # rows in the mix. Live rows always sort to the top.

    if df.empty:
        alert_data = df
        alert_data_display = df
    else:
        alert_data = df[df["final_prediction"] == 1].copy()
        alert_data["is_live"] = alert_data["source"] == "Live"
        alert_data = alert_data.sort_values(
            by=["is_live", "behaviour_score"],
            ascending=[False, False]
        )
        alert_data_display = alert_data.head(300)

    # -----------------------------
    # Alert Counts
    # -----------------------------

    if df.empty:
        critical_count = 0
        high_count = 0
        medium_count = 0
        low_count = 0
    else:
        critical_count = len(df[df["threat_level"] == "Critical"])
        high_count = len(df[df["threat_level"] == "High"])
        medium_count = len(df[df["threat_level"] == "Medium"])
        low_count = len(df[df["threat_level"] == "Low"])

    # -----------------------------
    # Highest Risk Province / Department
    # -----------------------------

    if df.empty or df["final_prediction"].sum() == 0:

        highest_province = "N/A"
        highest_department = "N/A"

    else:

        province_risk = (
            df.groupby("province")["final_prediction"]
            .sum()
            .sort_values(ascending=False)
        )

        highest_province = province_risk.index[0] if len(province_risk) else "N/A"

        department_risk = (
            df.groupby("department")["final_prediction"]
            .sum()
            .sort_values(ascending=False)
        )

        highest_department = department_risk.index[0] if len(department_risk) else "N/A"

    # -----------------------------
    # AI Threat Level
    # -----------------------------

    if critical_count > 0:

        ai_level = "CRITICAL"

    elif high_count > 0:

        ai_level = "HIGH"

    else:

        ai_level = "NORMAL"

    # -----------------------------
    # Verification signature + status
    # -----------------------------
    # Same subset/order the template loops over for its
    # "critical incidents" list, so the fingerprint always
    # matches what the analyst actually reviewed.

    if df.empty:
        critical_rows_ids = []
        high_rows_ids = []
    else:
        critical_rows_ids = alert_data[
            alert_data["threat_level"] == "Critical"
        ]["user_id"].tolist()

        high_rows_ids = alert_data[
            alert_data["threat_level"] == "High"
        ]["user_id"].tolist()

    alert_signature = build_alert_signature(
        critical_rows_ids,
        high_rows_ids,
        critical_count,
        high_count
    )

    already_verified = is_signature_verified(alert_signature)

    recent_verifications = get_recent_verifications(10)

    evidence_log = get_unauthorised_access_evidence(50)

    return render_template(

        "alerts.html",

        user=session["user"],

        role=session["role"],

        alerts=alert_data_display.to_dict("records"),

        total_alert_count=len(alert_data),

        critical_count=critical_count,

        high_count=high_count,

        medium_count=medium_count,

        low_count=low_count,

        highest_province=highest_province,

        highest_department=highest_department,

        ai_level=ai_level,

        alert_signature=alert_signature,

        already_verified=already_verified,

        recent_verifications=recent_verifications,

        evidence_log=evidence_log,

        live_count=int((df["source"] == "Live").sum()) if not df.empty else 0,

        current_time=datetime.now().strftime("%d %B %Y %I:%M %p"),

    )


# ============================================================
# ALERTS - VERIFY (saves the sign-off, silences the siren)
# ============================================================

@app.route("/alerts/verify", methods=["POST"])
def verify_alert():

    if "user" not in session:
        return jsonify({"error": "You need to be logged in."}), 401

    # Verifying an alert is a Security Analyst's job specifically --
    # not an Administrator's, and not an Employee's. This is checked
    # twice: once against the session role, and again by looking up the
    # username the analyst types into the form against the real staff
    # database, so a stale or tampered session can't sneak through.
    if session.get("role") != "Security Analyst":
        return jsonify({"error": "Only a Security Analyst can verify alerts."}), 403

    payload = request.get_json(silent=True) or {}

    signature = (payload.get("signature") or "").strip()
    name = (payload.get("name") or "").strip()
    badge = (payload.get("badge") or "").strip()
    username = (payload.get("username") or "").strip()
    notes = (payload.get("notes") or "").strip()
    critical_count = payload.get("critical_count", 0)
    high_count = payload.get("high_count", 0)

    if not signature or not name or not badge or not username:
        return jsonify({
            "error": "Name, badge number, your username, and a valid alert signature are all required."
        }), 400

    if username != session["user"]:
        return jsonify({
            "error": "That username doesn't match the account you're logged in as."
        }), 403

    staff = get_staff(username)

    if not staff or staff["role"] != "Security Analyst":
        return jsonify({
            "error": "That account isn't a registered Security Analyst -- verification refused."
        }), 403

    save_verification(
        signature=signature,
        name=name,
        badge=badge,
        notes=notes,
        critical_count=critical_count,
        high_count=high_count,
        verified_by=session["user"],
    )

    log_staff_action(
        username=session["user"],
        role=session["role"],
        action="Verified alert batch",
        target=f"{critical_count} critical / {high_count} high",
    )

    return jsonify({
        "status": "ok",
        "verified_at": datetime.now().strftime("%d %B %Y %I:%M %p"),
    })


# ============================================================
# ANALYTICS
# ============================================================

@app.route("/analytics")
def analytics():

    if "user" not in session:
        return redirect(url_for("login"))

    if session.get("role") == "Employee":
        return redirect(url_for("employee_portal"))

    if session.get("role") == "Security Analyst":
        return redirect(url_for("alerts"))

    data = live_dashboard_data()

    return render_template(

        "analytics.html",

        user=session["user"],

        role=session["role"],

        threat_labels=json.dumps(
            data["threat_labels"]
        ),

        threat_values=json.dumps(
            data["threat_values"]
        ),

        province_labels=json.dumps(
            data["province_labels"]
        ),

        province_values=json.dumps(
            data["province_values"]
        ),

        department_labels=json.dumps(
            data["department_labels"]
        ),

        department_values=json.dumps(
            data["department_values"]
        ),

        role_labels=json.dumps(
            data["role_labels"]
        ),

        role_values=json.dumps(
            data["role_values"]
        )

    )


# ============================================================
# REPORTS
# ============================================================

@app.route("/reports")
def reports():

    if "user" not in session:
        return redirect(url_for("login"))

    if session.get("role") == "Employee":
        return redirect(url_for("employee_portal"))

    if session.get("role") == "Security Analyst":
        return redirect(url_for("alerts"))

    df = get_combined_activity_df()

    if df.empty:
        report = {
            "total_employees": 0,
            "total_alerts": 0,
            "high": 0,
            "critical": 0,
        }
    else:
        report = {
            "total_employees": df["user_id"].nunique(),
            "total_alerts": int(df["final_prediction"].sum()),
            "high": len(df[df["threat_level"] == "High"]),
            "critical": len(df[df["threat_level"] == "Critical"]),
        }

    return render_template(

        "reports.html",

        user=session["user"],

        role=session["role"],

        report=report

    )


# ============================================================
# DOWNLOADS
# ============================================================

@app.route("/download/province")
def download_province():

    return send_file(

        "reports/Province_Risk_Report.csv",

        as_attachment=True

    )


@app.route("/download/department")
def download_department():

    return send_file(

        "reports/Department_Risk_Report.csv",

        as_attachment=True

    )


@app.route("/download/alerts")
def download_alerts():

    return send_file(

        "reports/Security_Alerts.csv",

        as_attachment=True

    )


@app.route("/download/final")
def download_final():

    return send_file(

        "data/SIZOKUTHOLA_Final_Dataset.csv",

        as_attachment=True

    )
# ============================================================
# SETTINGS
# ============================================================

@app.route("/settings")
def settings():

    if "user" not in session:
        return redirect(url_for("login"))

    if session.get("role") == "Employee":
        return redirect(url_for("employee_portal"))

    if session.get("role") == "Security Analyst":
        return redirect(url_for("alerts"))

    system_information = {

        "system_name": "SIZOKUTHOLA",

        "version": "1.0",

        "developer": "Dipuo Princess Masoga",

        "organisation": "Department of Basic Education",

        "model_one": "Isolation Forest",

        "model_two": "K-Means Clustering",

        "dataset": "SIZOKUTHOLA_Final_Dataset.csv",

        "records": len(activities),

        "employees": activities["user_id"].nunique()

    }

    return render_template(

        "settings.html",

        user=session["user"],

        role=session["role"],

        info=system_information,

        all_staff=get_all_staff(),

        staff_role_options=["Administrator", "Security Analyst"],

        staff_audit_log=get_staff_audit_log(20),

        staff_added=request.args.get("staff_added"),

        staff_message=request.args.get("staff_msg"),

    )


@app.route("/staff/add", methods=["POST"])
def staff_add():

    if "user" not in session:
        return redirect(url_for("login"))

    if session.get("role") != "Administrator":
        return redirect(url_for("login"))

    success, message = add_staff(

        username=request.form.get("username", ""),

        password=request.form.get("password", ""),

        display_name=request.form.get("display_name", ""),

        role=request.form.get("role", ""),

    )

    if success:

        log_staff_action(
            username=session["user"],
            role=session["role"],
            action="Added staff account",
            target=request.form.get("username", ""),
        )

    return redirect(url_for("settings", staff_added=("1" if success else "0"), staff_msg=message))


@app.route("/staff/delete", methods=["POST"])
def staff_delete():

    if "user" not in session:
        return redirect(url_for("login"))

    if session.get("role") != "Administrator":
        return redirect(url_for("login"))

    username = request.form.get("username", "")

    if username == session["user"]:
        return redirect(url_for("settings", staff_added="0", staff_msg="You can't remove the account you're currently logged in as."))

    if username:
        delete_staff(username)

        log_staff_action(
            username=session["user"],
            role=session["role"],
            action="Removed staff account",
            target=username,
        )

    return redirect(url_for("settings"))


# ============================================================
# PROFILE
# ============================================================

@app.route("/profile")
def profile():

    if "user" not in session:
        return redirect(url_for("login"))

    profile = {

        "username": session["user"],

        "role": session["role"],

        "organisation": "Department of Basic Education",

        "system": "SIZOKUTHOLA"

    }

    return render_template(

        "profile.html",

        profile=profile,

        user=session["user"],

        role=session["role"]

    )


# ============================================================
# PAGE NOT FOUND
# ============================================================

@app.errorhandler(404)
def page_not_found(error):

    return render_template(

        "404.html"

    ), 404


# ============================================================
# INTERNAL SERVER ERROR
# ============================================================

@app.errorhandler(500)
def internal_error(error):

    return render_template(

        "500.html"

    ), 500


# ============================================================
# RUN APPLICATION
# ============================================================

if __name__ == "__main__":

    app.run(

        debug=True,

        host="127.0.0.1",

        port=5000

    )