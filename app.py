import sqlite3
import time
import os
import base64
import csv
import json
from io import StringIO
from datetime import timedelta, datetime
from functools import wraps
from flask import Flask, render_template, request, session, redirect, url_for, make_response, jsonify, Response
from werkzeug.security import generate_password_hash, check_password_hash
from werkzeug.utils import secure_filename
from flask_wtf import CSRFProtect

app = Flask(__name__)
app.secret_key = os.environ.get("SECRET_KEY", "dev-key-changez-moi-avant-la-mise-en-ligne")

# Chemin absolu vers la base, basé sur l'emplacement de ce fichier — fonctionne peu importe
# le dossier depuis lequel le processus est lancé (console Bash, serveur WSGI, etc.)
BASE_DIR = os.path.dirname(os.path.abspath(__file__))
DB_PATH = os.path.join(BASE_DIR, "database.db")

# Cookies de session sécurisés : inaccessibles en JS, bloqués sur requêtes cross-site,
# et transmis uniquement en HTTPS une fois en ligne (Render définit la variable RENDER automatiquement)
app.config["SESSION_COOKIE_HTTPONLY"] = True
app.config["SESSION_COOKIE_SAMESITE"] = "Lax"
app.config["SESSION_COOKIE_SECURE"] = bool(os.environ.get("RENDER"))

# Déconnexion automatique après 2h d'inactivité
app.config["PERMANENT_SESSION_LIFETIME"] = timedelta(hours=2)

# Limite la taille des requêtes (upload de fichiers compris) à 5 Mo pour éviter les abus
app.config["MAX_CONTENT_LENGTH"] = 5 * 1024 * 1024

csrf = CSRFProtect(app)

UPLOAD_FOLDER = os.path.join(app.static_folder, "uploads")
os.makedirs(UPLOAD_FOLDER, exist_ok=True)
ALLOWED_UPLOAD_EXTENSIONS = {"txt", "log", "csv", "json", "png", "jpg", "jpeg", "zip", "pcap"}

CATEGORIES = ["Web", "Crypto", "Forensic", "Stéganographie", "Réseau", "Divers"]
CATEGORY_ICONS = {"Web": "🌐", "Crypto": "🔐", "Forensic": "🔍", "Stéganographie": "🖼️", "Réseau": "📡", "Divers": "🎲"}

# Code à donner à ceux qui doivent pouvoir s'inscrire (ta classe). Change-le via une variable
# d'environnement REGISTRATION_CODE une fois en ligne, sinon "ctf2026" par défaut en local.
REGISTRATION_CODE = os.environ.get("REGISTRATION_CODE", "ctf2026")

# Anti brute-force : on garde les tentatives ratées en mémoire (simple, suffisant pour un projet scolaire)
MAX_ATTEMPTS = 5
LOCKOUT_SECONDS = 60
login_attempts = {}     # clé = username, valeur = liste des timestamps des échecs
flag_attempts = {}      # clé = (user_id, challenge_id), valeur = liste des timestamps des échecs
register_attempts = {}  # clé = adresse IP, valeur = liste des timestamps de tentatives d'inscription


def is_locked_out(attempts_dict, key):
    now = time.time()
    attempts_dict[key] = [t for t in attempts_dict.get(key, []) if now - t < LOCKOUT_SECONDS]
    return len(attempts_dict[key]) >= MAX_ATTEMPTS


def record_attempt(attempts_dict, key):
    attempts_dict.setdefault(key, []).append(time.time())


def clear_attempts(attempts_dict, key):
    attempts_dict.pop(key, None)


def get_db():
    connexion = sqlite3.connect(DB_PATH)
    connexion.row_factory = sqlite3.Row
    return connexion


def extension_autorisee(filename):
    return "." in filename and filename.rsplit(".", 1)[1].lower() in ALLOWED_UPLOAD_EXTENSIONS


def log_admin_action(action, details=""):
    db = get_db()
    db.execute(
        "INSERT INTO admin_logs (admin_username, action, details, timestamp) VALUES (?, ?, ?, ?)",
        (session.get("username", "?"), action, details, datetime.now().strftime("%Y-%m-%d %H:%M:%S"))
    )
    db.commit()
    db.close()


def login_required(f):
    @wraps(f)
    def decorated_function(*args, **kwargs):
        if "user_id" not in session:
            return redirect(url_for("index"))
        return f(*args, **kwargs)
    return decorated_function


def admin_required(f):
    @wraps(f)
    def decorated_function(*args, **kwargs):
        if "user_id" not in session:
            return redirect(url_for("index"))
        if not session.get("is_admin"):
            return redirect(url_for("dashboard"))
        return f(*args, **kwargs)
    return decorated_function


def api_login_required(f):
    @wraps(f)
    def decorated_function(*args, **kwargs):
        if "user_id" not in session:
            return jsonify({"error": "Authentification requise"}), 401
        return f(*args, **kwargs)
    return decorated_function


@app.after_request
def add_security_headers(response):
    response.headers["X-Content-Type-Options"] = "nosniff"
    response.headers["X-Frame-Options"] = "DENY"
    response.headers["Referrer-Policy"] = "no-referrer-when-downgrade"
    return response


@app.route("/")
def index():
    if "user_id" in session:
        return redirect(url_for("dashboard"))
    return render_template("index.html")


@app.route("/login", methods=["GET"])
def login_page():
    if "user_id" in session:
        return redirect(url_for("dashboard"))
    return render_template("login.html")


@app.route("/login", methods=["POST"])
def login():
    username = request.form.get("username")
    password = request.form.get("password")

    if is_locked_out(login_attempts, username):
        return render_template("login.html", error="Trop de tentatives. Réessaie dans une minute.")

    db = get_db()
    user = db.execute("SELECT * FROM users WHERE username = ?", (username,)).fetchone()
    db.close()

    if user and check_password_hash(user["password"], password):
        clear_attempts(login_attempts, username)
        session.permanent = True
        session["user_id"] = user["id"]
        session["username"] = user["username"]
        session["is_admin"] = bool(user["is_admin"])
        return redirect(url_for("dashboard"))
    else:
        record_attempt(login_attempts, username)
        return render_template("login.html", error="Nom d'utilisateur ou mot de passe incorrect.")


@app.route("/register", methods=["GET", "POST"])
def register():
    if request.method == "GET":
        return render_template("register.html")

    if is_locked_out(register_attempts, request.remote_addr):
        return render_template("register.html", error="Trop d'inscriptions depuis cette adresse. Réessaie plus tard.")

    record_attempt(register_attempts, request.remote_addr)

    username = request.form.get("username", "").strip()
    password = request.form.get("password", "")
    invite_code = request.form.get("invite_code", "")

    if invite_code != REGISTRATION_CODE:
        return render_template("register.html", error="Code d'invitation incorrect.")

    if len(username) < 3:
        return render_template("register.html", error="Le nom d'utilisateur doit faire au moins 3 caractères.")

    if len(password) < 4:
        return render_template("register.html", error="Le mot de passe doit faire au moins 4 caractères.")

    db = get_db()
    existing_user = db.execute("SELECT * FROM users WHERE username = ?", (username,)).fetchone()

    if existing_user:
        db.close()
        return render_template("register.html", error="Ce nom d'utilisateur est déjà pris.")

    hashed_password = generate_password_hash(password)
    db.execute("INSERT INTO users (username, password) VALUES (?, ?)", (username, hashed_password))
    db.commit()
    db.close()

    return render_template("login.html", error="Compte créé avec succès ! Tu peux te connecter.")


@app.route("/api/docs")
def api_docs():
    endpoints = [
        {"method": "GET", "path": "/api/me", "auth": "Session requise", "description": "Retourne le pseudo et le statut admin de l'utilisateur connecté."},
        {"method": "GET", "path": "/api/challenges", "auth": "Session requise", "description": "Liste tous les challenges. Filtre optionnel : ?category=Web"},
        {"method": "GET", "path": "/api/challenges/<id>", "auth": "Session requise", "description": "Détail d'un challenge précis."},
        {"method": "POST", "path": "/api/challenges/<id>/submit", "auth": "Session requise", "description": "Soumet un flag. Corps JSON attendu : {\"flag\": \"CTF{...}\"}"},
        {"method": "GET", "path": "/api/leaderboard", "auth": "Session requise", "description": "Classement de tous les utilisateurs par points."},
        {"method": "GET", "path": "/api/profile", "auth": "Session requise", "description": "Statistiques de l'utilisateur connecté (points, challenges résolus)."},
    ]
    return render_template("api_docs.html", endpoints=endpoints)


@app.route("/dashboard")
@login_required
def dashboard():
    return render_template("dashboard.html", username=session["username"])


@app.route("/challenges")
@login_required
def challenges():
    selected_category = request.args.get("category", "Toutes")
    search = request.args.get("search", "").strip()
    sort = request.args.get("sort", "default")

    sort_clauses = {
        "points_desc": "points DESC",
        "points_asc": "points ASC",
        "name_asc": "name ASC",
        "difficulty": "CASE difficulty WHEN 'Facile' THEN 1 WHEN 'Moyen' THEN 2 ELSE 3 END ASC"
    }
    order_by = sort_clauses.get(sort, "id ASC")

    query = "SELECT * FROM challenges WHERE 1=1"
    params = []

    if selected_category and selected_category != "Toutes":
        query += " AND category = ?"
        params.append(selected_category)

    if search:
        query += " AND name LIKE ?"
        params.append(f"%{search}%")

    query += f" ORDER BY {order_by}"

    db = get_db()
    all_challenges = db.execute(query, params).fetchall()
    solved_ids = {
        row["challenge_id"] for row in db.execute(
            "SELECT challenge_id FROM solves WHERE user_id = ?", (session["user_id"],)
        ).fetchall()
    }
    solve_counts = db.execute("SELECT challenge_id, COUNT(*) AS cnt FROM solves GROUP BY challenge_id").fetchall()
    db.close()

    solve_counts_map = {row["challenge_id"]: row["cnt"] for row in solve_counts}

    challenges_list = [{
        "id": c["id"],
        "name": c["name"],
        "category": c["category"],
        "difficulty": c["difficulty"],
        "points": c["points"],
        "solved": c["id"] in solved_ids,
        "solve_count": solve_counts_map.get(c["id"], 0)
    } for c in all_challenges]

    resp = make_response(render_template(
        "challenges.html",
        challenges=challenges_list,
        categories=CATEGORIES,
        category_icons=CATEGORY_ICONS,
        selected_category=selected_category,
        search=search,
        sort=sort
    ))
    resp.headers["X-Secret-Flag"] = "CTF{check_your_headers}"
    resp.set_cookie("debug_session", base64.b64encode(b"CTF{cookie_monster}").decode())
    return resp


@app.route("/challenge/<int:challenge_id>")
@login_required
def challenge_detail(challenge_id):
    db = get_db()
    c = db.execute("SELECT * FROM challenges WHERE id = ?", (challenge_id,)).fetchone()

    if not c:
        db.close()
        return redirect(url_for("challenges"))

    is_solved = db.execute(
        "SELECT 1 FROM solves WHERE user_id = ? AND challenge_id = ?", (session["user_id"], challenge_id)
    ).fetchone() is not None

    hint_unlocked = db.execute(
        "SELECT 1 FROM hints_used WHERE user_id = ? AND challenge_id = ?", (session["user_id"], challenge_id)
    ).fetchone() is not None

    solve_count = db.execute(
        "SELECT COUNT(*) AS n FROM solves WHERE challenge_id = ?", (challenge_id,)
    ).fetchone()["n"]

    first_blood_row = db.execute("""
        SELECT u.username FROM solves s
        JOIN users u ON u.id = s.user_id
        WHERE s.challenge_id = ?
        ORDER BY s.id ASC LIMIT 1
    """, (challenge_id,)).fetchone()
    db.close()

    challenge = {
        "id": c["id"],
        "name": c["name"],
        "description": c["description"],
        "category": c["category"],
        "difficulty": c["difficulty"],
        "points": c["points"],
        "solved": is_solved,
        "has_hint": bool(c["hint"] and c["hint"].strip()),
        "hint_cost": c["hint_cost"],
        "hint_unlocked": hint_unlocked,
        "hint_text": c["hint"],
        "writeup": c["writeup"] if is_solved else None,
        "attachment": c["attachment"] if c["attachment"] else None,
        "solve_count": solve_count,
        "first_blood": first_blood_row["username"] if first_blood_row else None
    }

    return render_template("challenge_detail.html", challenge=challenge)


@app.route("/hint/<int:challenge_id>", methods=["POST"])
@login_required
def unlock_hint(challenge_id):
    db = get_db()
    db.execute(
        "INSERT OR IGNORE INTO hints_used (user_id, challenge_id) VALUES (?, ?)",
        (session["user_id"], challenge_id)
    )
    db.commit()
    db.close()
    return redirect(url_for("challenges"))


@app.route("/leaderboard")
@login_required
def leaderboard():
    db = get_db()
    rankings = db.execute("""
        SELECT u.username,
               COALESCE(sp.total, 0) - COALESCE(hc.total, 0) AS total_points
        FROM users u
        LEFT JOIN (
            SELECT solves.user_id AS uid, SUM(challenges.points) AS total
            FROM solves JOIN challenges ON solves.challenge_id = challenges.id
            GROUP BY solves.user_id
        ) sp ON sp.uid = u.id
        LEFT JOIN (
            SELECT hints_used.user_id AS uid, SUM(challenges.hint_cost) AS total
            FROM hints_used JOIN challenges ON hints_used.challenge_id = challenges.id
            GROUP BY hints_used.user_id
        ) hc ON hc.uid = u.id
        ORDER BY total_points DESC
    """).fetchall()
    db.close()

    return render_template("leaderboard.html", rankings=rankings, current_user=session["username"])


@app.route("/submit/<int:challenge_id>", methods=["POST"])
@login_required
def submit_flag(challenge_id):
    attempt_key = (session["user_id"], challenge_id)

    if is_locked_out(flag_attempts, attempt_key):
        return redirect(url_for("challenges"))

    submitted_flag = request.form.get("flag", "").strip()

    db = get_db()
    challenge = db.execute("SELECT * FROM challenges WHERE id = ?", (challenge_id,)).fetchone()

    if challenge and submitted_flag == challenge["flag"]:
        db.execute(
            "INSERT OR IGNORE INTO solves (user_id, challenge_id) VALUES (?, ?)",
            (session["user_id"], challenge_id)
        )
        db.commit()
        clear_attempts(flag_attempts, attempt_key)
    else:
        record_attempt(flag_attempts, attempt_key)

    db.close()
    return redirect(url_for("challenges"))


@app.route("/profile")
@login_required
def profile():
    db = get_db()
    solved_challenges = db.execute("""
        SELECT challenges.id, challenges.name, challenges.points, challenges.category
        FROM solves
        JOIN challenges ON solves.challenge_id = challenges.id
        WHERE solves.user_id = ?
    """, (session["user_id"],)).fetchall()

    hint_costs = db.execute("""
        SELECT COALESCE(SUM(challenges.hint_cost), 0) AS total
        FROM hints_used
        JOIN challenges ON hints_used.challenge_id = challenges.id
        WHERE hints_used.user_id = ?
    """, (session["user_id"],)).fetchone()

    total_challenges = db.execute("SELECT COUNT(*) AS n FROM challenges").fetchone()["n"]

    first_blood_count = db.execute("""
        SELECT COUNT(*) AS n FROM solves s
        WHERE s.user_id = ? AND s.id IN (SELECT MIN(id) FROM solves GROUP BY challenge_id)
    """, (session["user_id"],)).fetchone()["n"]
    db.close()

    total_points = sum(c["points"] for c in solved_challenges) - hint_costs["total"]
    solved_count = len(solved_challenges)
    categories_solved = {c["category"] for c in solved_challenges}

    badges = [
        {"name": "Premier flag", "icon": "🚩", "description": "Résous ton premier challenge.", "unlocked": solved_count >= 1},
        {"name": "Cinq d'un coup", "icon": "🔥", "description": "Résous 5 challenges.", "unlocked": solved_count >= 5},
        {"name": "Collection complète", "icon": "🏅", "description": "Résous tous les challenges disponibles.", "unlocked": total_challenges > 0 and solved_count == total_challenges},
        {"name": "Sang neuf", "icon": "🩸", "description": "Sois le premier à résoudre un challenge.", "unlocked": first_blood_count >= 1},
        {"name": "Décodeur", "icon": "🔐", "description": "Résous un challenge de catégorie Crypto.", "unlocked": "Crypto" in categories_solved},
        {"name": "Investigateur", "icon": "🔍", "description": "Résous un challenge de catégorie Forensic.", "unlocked": "Forensic" in categories_solved},
    ]

    return render_template(
        "profile.html",
        username=session["username"],
        total_points=total_points,
        solved_challenges=solved_challenges,
        badges=badges
    )


@app.route("/admin", methods=["GET", "POST"])
@admin_required
def admin_panel():
    db = get_db()

    if request.method == "POST":
        name = request.form.get("name")
        description = request.form.get("description")
        flag = request.form.get("flag")
        difficulty = request.form.get("difficulty")
        category = request.form.get("category")
        hint = request.form.get("hint", "")
        writeup = request.form.get("writeup", "")

        try:
            points = max(0, int(request.form.get("points", 0)))
        except (TypeError, ValueError):
            points = 0
        try:
            hint_cost = max(0, int(request.form.get("hint_cost") or 0))
        except (TypeError, ValueError):
            hint_cost = 0

        attachment_filename = ""
        uploaded_file = request.files.get("attachment")
        if uploaded_file and uploaded_file.filename:
            if extension_autorisee(uploaded_file.filename):
                attachment_filename = secure_filename(uploaded_file.filename)
                uploaded_file.save(os.path.join(UPLOAD_FOLDER, attachment_filename))

        db.execute(
            "INSERT INTO challenges (name, description, flag, points, difficulty, category, hint, hint_cost, writeup, attachment) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?)",
            (name, description, flag, points, difficulty, category, hint, hint_cost, writeup, attachment_filename)
        )
        db.commit()
        log_admin_action("Ajout challenge", name)

    all_challenges = db.execute("SELECT * FROM challenges").fetchall()

    total_users = db.execute("SELECT COUNT(*) AS n FROM users").fetchone()["n"]
    total_challenges = db.execute("SELECT COUNT(*) AS n FROM challenges").fetchone()["n"]
    total_solves = db.execute("SELECT COUNT(*) AS n FROM solves").fetchone()["n"]

    hardest_challenge = db.execute("""
        SELECT challenges.name, COUNT(solves.id) AS solve_count
        FROM challenges
        LEFT JOIN solves ON solves.challenge_id = challenges.id
        GROUP BY challenges.id
        ORDER BY solve_count ASC
        LIMIT 1
    """).fetchone()

    solve_counts = db.execute("""
        SELECT challenge_id, COUNT(*) AS solve_count
        FROM solves
        GROUP BY challenge_id
    """).fetchall()
    db.close()

    solve_counts_map = {row["challenge_id"]: row["solve_count"] for row in solve_counts}

    return render_template(
        "admin.html",
        all_challenges=all_challenges,
        categories=CATEGORIES,
        total_users=total_users,
        total_challenges=total_challenges,
        total_solves=total_solves,
        hardest_challenge=hardest_challenge,
        solve_counts_map=solve_counts_map
    )


@app.route("/admin/edit/<int:challenge_id>", methods=["GET", "POST"])
@admin_required
def admin_edit_challenge(challenge_id):
    db = get_db()

    if request.method == "POST":
        name = request.form.get("name")
        description = request.form.get("description")
        flag = request.form.get("flag")
        difficulty = request.form.get("difficulty")
        category = request.form.get("category")
        hint = request.form.get("hint", "")
        writeup = request.form.get("writeup", "")

        try:
            points = max(0, int(request.form.get("points", 0)))
        except (TypeError, ValueError):
            points = 0
        try:
            hint_cost = max(0, int(request.form.get("hint_cost") or 0))
        except (TypeError, ValueError):
            hint_cost = 0

        existing = db.execute("SELECT attachment FROM challenges WHERE id = ?", (challenge_id,)).fetchone()
        attachment_filename = existing["attachment"] if existing else ""

        uploaded_file = request.files.get("attachment")
        if uploaded_file and uploaded_file.filename and extension_autorisee(uploaded_file.filename):
            attachment_filename = secure_filename(uploaded_file.filename)
            uploaded_file.save(os.path.join(UPLOAD_FOLDER, attachment_filename))

        db.execute("""
            UPDATE challenges
            SET name = ?, description = ?, flag = ?, points = ?, difficulty = ?, category = ?, hint = ?, hint_cost = ?, writeup = ?, attachment = ?
            WHERE id = ?
        """, (name, description, flag, points, difficulty, category, hint, hint_cost, writeup, attachment_filename, challenge_id))
        db.commit()
        db.close()
        log_admin_action("Modification challenge", name)
        return redirect(url_for("admin_panel"))

    challenge = db.execute("SELECT * FROM challenges WHERE id = ?", (challenge_id,)).fetchone()
    db.close()

    return render_template("admin_edit.html", challenge=challenge, categories=CATEGORIES)


@app.route("/admin/delete/<int:challenge_id>", methods=["POST"])
@admin_required
def admin_delete_challenge(challenge_id):
    db = get_db()
    challenge = db.execute("SELECT name FROM challenges WHERE id = ?", (challenge_id,)).fetchone()
    db.execute("DELETE FROM challenges WHERE id = ?", (challenge_id,))
    db.execute("DELETE FROM solves WHERE challenge_id = ?", (challenge_id,))
    db.commit()
    db.close()
    if challenge:
        log_admin_action("Suppression challenge", challenge["name"])
    return redirect(url_for("admin_panel"))


@app.route("/admin/users")
@admin_required
def admin_users():
    db = get_db()
    users = db.execute("""
        SELECT u.id, u.username, u.is_admin,
               COALESCE(sp.total, 0) - COALESCE(hc.total, 0) AS total_points
        FROM users u
        LEFT JOIN (
            SELECT solves.user_id AS uid, SUM(challenges.points) AS total
            FROM solves JOIN challenges ON solves.challenge_id = challenges.id
            GROUP BY solves.user_id
        ) sp ON sp.uid = u.id
        LEFT JOIN (
            SELECT hints_used.user_id AS uid, SUM(challenges.hint_cost) AS total
            FROM hints_used JOIN challenges ON hints_used.challenge_id = challenges.id
            GROUP BY hints_used.user_id
        ) hc ON hc.uid = u.id
        ORDER BY u.username COLLATE NOCASE ASC
    """).fetchall()
    db.close()

    return render_template("admin_users.html", users=users, current_user_id=session["user_id"])


@app.route("/admin/users/<int:user_id>/toggle-admin", methods=["POST"])
@admin_required
def admin_toggle_admin(user_id):
    if user_id == session["user_id"]:
        return redirect(url_for("admin_users"))

    db = get_db()
    user = db.execute("SELECT username, is_admin FROM users WHERE id = ?", (user_id,)).fetchone()
    if user:
        new_status = 0 if user["is_admin"] else 1
        db.execute("UPDATE users SET is_admin = ? WHERE id = ?", (new_status, user_id))
        db.commit()
        log_admin_action(
            "Retrait admin" if new_status == 0 else "Promotion admin",
            user["username"]
        )
    db.close()
    return redirect(url_for("admin_users"))


@app.route("/admin/users/<int:user_id>/delete", methods=["POST"])
@admin_required
def admin_delete_user(user_id):
    if user_id == session["user_id"]:
        return redirect(url_for("admin_users"))

    db = get_db()
    user = db.execute("SELECT username FROM users WHERE id = ?", (user_id,)).fetchone()
    db.execute("DELETE FROM solves WHERE user_id = ?", (user_id,))
    db.execute("DELETE FROM hints_used WHERE user_id = ?", (user_id,))
    db.execute("DELETE FROM users WHERE id = ?", (user_id,))
    db.commit()
    db.close()
    if user:
        log_admin_action("Suppression utilisateur", user["username"])
    return redirect(url_for("admin_users"))


@app.route("/admin/users/<int:user_id>/reset-password", methods=["POST"])
@admin_required
def admin_reset_password(user_id):
    new_password = request.form.get("new_password", "")

    if len(new_password) < 4:
        return redirect(url_for("admin_users"))

    db = get_db()
    user = db.execute("SELECT username FROM users WHERE id = ?", (user_id,)).fetchone()
    hashed = generate_password_hash(new_password)
    db.execute("UPDATE users SET password = ? WHERE id = ?", (hashed, user_id))
    db.commit()
    db.close()
    if user:
        log_admin_action("Réinitialisation mot de passe", user["username"])
    return redirect(url_for("admin_users"))


@app.route("/admin/export-leaderboard")
@admin_required
def admin_export_leaderboard():
    db = get_db()
    rankings = db.execute("""
        SELECT u.username,
               COALESCE(sp.total, 0) - COALESCE(hc.total, 0) AS total_points
        FROM users u
        LEFT JOIN (
            SELECT solves.user_id AS uid, SUM(challenges.points) AS total
            FROM solves JOIN challenges ON solves.challenge_id = challenges.id
            GROUP BY solves.user_id
        ) sp ON sp.uid = u.id
        LEFT JOIN (
            SELECT hints_used.user_id AS uid, SUM(challenges.hint_cost) AS total
            FROM hints_used JOIN challenges ON hints_used.challenge_id = challenges.id
            GROUP BY hints_used.user_id
        ) hc ON hc.uid = u.id
        ORDER BY total_points DESC
    """).fetchall()
    db.close()

    output = StringIO()
    writer = csv.writer(output)
    writer.writerow(["Rang", "Nom d'utilisateur", "Points"])
    for i, row in enumerate(rankings, start=1):
        writer.writerow([i, row["username"], row["total_points"]])

    return Response(
        output.getvalue(),
        mimetype="text/csv",
        headers={"Content-Disposition": "attachment; filename=classement.csv"}
    )


@app.route("/admin/logs")
@admin_required
def admin_logs():
    db = get_db()
    logs = db.execute(
        "SELECT * FROM admin_logs ORDER BY id DESC LIMIT 200"
    ).fetchall()
    db.close()

    return render_template("admin_logs.html", logs=logs)


@app.route("/admin/import", methods=["GET", "POST"])
@admin_required
def admin_import_challenges():
    if request.method == "GET":
        return render_template("admin_import.html")

    uploaded_file = request.files.get("import_file")
    if not uploaded_file or not uploaded_file.filename:
        return render_template("admin_import.html", error="Aucun fichier sélectionné.")

    filename = uploaded_file.filename.lower()
    content = uploaded_file.read().decode("utf-8", errors="replace")

    try:
        if filename.endswith(".json"):
            data = json.loads(content)
            if not isinstance(data, list):
                raise ValueError("le fichier JSON doit contenir une liste de challenges (entre [ ]).")
            challenges_to_add = data
        elif filename.endswith(".csv"):
            challenges_to_add = list(csv.DictReader(StringIO(content)))
        else:
            return render_template("admin_import.html", error="Format non supporté. Utilise un fichier .csv ou .json.")
    except (json.JSONDecodeError, ValueError) as e:
        return render_template("admin_import.html", error=f"Fichier invalide : {e}")

    required_fields = ["name", "description", "flag", "points", "difficulty", "category"]
    db = get_db()
    added = 0
    skipped = 0
    errors = []

    for i, item in enumerate(challenges_to_add, start=1):
        missing = [f for f in required_fields if not item.get(f)]
        if missing:
            errors.append(f"Ligne {i} : champs manquants ({', '.join(missing)})")
            continue

        existing = db.execute("SELECT COUNT(*) FROM challenges WHERE name = ?", (item["name"],)).fetchone()[0]
        if existing:
            skipped += 1
            continue

        try:
            points = max(0, int(item.get("points", 0)))
        except (TypeError, ValueError):
            points = 0
        try:
            hint_cost = max(0, int(item.get("hint_cost") or 0))
        except (TypeError, ValueError):
            hint_cost = 0

        category = item["category"] if item["category"] in CATEGORIES else "Divers"
        difficulty = item["difficulty"] if item["difficulty"] in ["Facile", "Moyen", "Difficile"] else "Facile"

        db.execute(
            "INSERT INTO challenges (name, description, flag, points, difficulty, category, hint, hint_cost, writeup) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?)",
            (item["name"], item["description"], item["flag"], points, difficulty, category, item.get("hint", ""), hint_cost, item.get("writeup", ""))
        )
        added += 1

    db.commit()
    db.close()

    if added:
        log_admin_action("Import en masse", f"{added} ajouté(s), {skipped} ignoré(s) (déjà existants)")

    success = f"{added} challenge(s) ajouté(s), {skipped} ignoré(s) (nom déjà utilisé)." if (added or skipped) else None
    return render_template("admin_import.html", success=success, errors=errors)


@app.route("/settings", methods=["GET", "POST"])
@login_required
def settings():
    error = None
    success = None

    if request.method == "POST":
        current_password = request.form.get("current_password")
        new_password = request.form.get("new_password")
        confirm_password = request.form.get("confirm_password")

        db = get_db()
        user = db.execute("SELECT * FROM users WHERE id = ?", (session["user_id"],)).fetchone()

        if not check_password_hash(user["password"], current_password):
            error = "Mot de passe actuel incorrect."
        elif new_password != confirm_password:
            error = "Les nouveaux mots de passe ne correspondent pas."
        elif len(new_password) < 4:
            error = "Le nouveau mot de passe est trop court."
        else:
            hashed = generate_password_hash(new_password)
            db.execute("UPDATE users SET password = ? WHERE id = ?", (hashed, session["user_id"]))
            db.commit()
            success = "Mot de passe mis à jour avec succès."

        db.close()

    return render_template("settings.html", error=error, success=success)


@app.route("/logout")
def logout():
    session.clear()
    return redirect(url_for("index"))


@app.route("/api/me")
@api_login_required
def api_me():
    return jsonify({
        "username": session["username"],
        "is_admin": bool(session.get("is_admin"))
    })


@app.route("/api/challenges")
@api_login_required
def api_challenges():
    category = request.args.get("category")

    db = get_db()
    if category:
        rows = db.execute("SELECT * FROM challenges WHERE category = ?", (category,)).fetchall()
    else:
        rows = db.execute("SELECT * FROM challenges").fetchall()

    solved_ids = {
        row["challenge_id"] for row in db.execute(
            "SELECT challenge_id FROM solves WHERE user_id = ?", (session["user_id"],)
        ).fetchall()
    }
    db.close()

    result = [{
        "id": c["id"],
        "name": c["name"],
        "description": c["description"],
        "category": c["category"],
        "difficulty": c["difficulty"],
        "points": c["points"],
        "solved": c["id"] in solved_ids
    } for c in rows]

    return jsonify(result)


@app.route("/api/challenges/<int:challenge_id>")
@api_login_required
def api_challenge_detail(challenge_id):
    db = get_db()
    c = db.execute("SELECT * FROM challenges WHERE id = ?", (challenge_id,)).fetchone()
    db.close()

    if not c:
        return jsonify({"error": "Challenge introuvable"}), 404

    return jsonify({
        "id": c["id"],
        "name": c["name"],
        "description": c["description"],
        "category": c["category"],
        "difficulty": c["difficulty"],
        "points": c["points"]
    })


@app.route("/api/challenges/<int:challenge_id>/submit", methods=["POST"])
@api_login_required
def api_submit_flag(challenge_id):
    attempt_key = (session["user_id"], challenge_id)

    if is_locked_out(flag_attempts, attempt_key):
        return jsonify({"error": "Trop de tentatives, réessaie plus tard"}), 429

    data = request.get_json(silent=True) or {}
    submitted_flag = (data.get("flag") or "").strip()

    db = get_db()
    challenge = db.execute("SELECT * FROM challenges WHERE id = ?", (challenge_id,)).fetchone()

    if not challenge:
        db.close()
        return jsonify({"error": "Challenge introuvable"}), 404

    if submitted_flag == challenge["flag"]:
        db.execute(
            "INSERT OR IGNORE INTO solves (user_id, challenge_id) VALUES (?, ?)",
            (session["user_id"], challenge_id)
        )
        db.commit()
        clear_attempts(flag_attempts, attempt_key)
        db.close()
        return jsonify({"correct": True, "points": challenge["points"]})
    else:
        record_attempt(flag_attempts, attempt_key)
        db.close()
        return jsonify({"correct": False})


csrf.exempt(api_submit_flag)


@app.route("/api/leaderboard")
@api_login_required
def api_leaderboard():
    db = get_db()
    rankings = db.execute("""
        SELECT u.username,
               COALESCE(sp.total, 0) - COALESCE(hc.total, 0) AS total_points
        FROM users u
        LEFT JOIN (
            SELECT solves.user_id AS uid, SUM(challenges.points) AS total
            FROM solves JOIN challenges ON solves.challenge_id = challenges.id
            GROUP BY solves.user_id
        ) sp ON sp.uid = u.id
        LEFT JOIN (
            SELECT hints_used.user_id AS uid, SUM(challenges.hint_cost) AS total
            FROM hints_used JOIN challenges ON hints_used.challenge_id = challenges.id
            GROUP BY hints_used.user_id
        ) hc ON hc.uid = u.id
        ORDER BY total_points DESC
    """).fetchall()
    db.close()

    result = [
        {"rank": i + 1, "username": row["username"], "points": row["total_points"]}
        for i, row in enumerate(rankings)
    ]
    return jsonify(result)


@app.route("/api/profile")
@api_login_required
def api_profile():
    db = get_db()
    solved_challenges = db.execute("""
        SELECT challenges.id, challenges.name, challenges.points
        FROM solves
        JOIN challenges ON solves.challenge_id = challenges.id
        WHERE solves.user_id = ?
    """, (session["user_id"],)).fetchall()

    hint_costs = db.execute("""
        SELECT COALESCE(SUM(challenges.hint_cost), 0) AS total
        FROM hints_used
        JOIN challenges ON hints_used.challenge_id = challenges.id
        WHERE hints_used.user_id = ?
    """, (session["user_id"],)).fetchone()
    db.close()

    total_points = sum(c["points"] for c in solved_challenges) - hint_costs["total"]

    return jsonify({
        "username": session["username"],
        "total_points": total_points,
        "solved_count": len(solved_challenges),
        "solved_challenges": [
            {"id": c["id"], "name": c["name"], "points": c["points"]} for c in solved_challenges
        ]
    })


@app.route("/public-leaderboard")
def public_leaderboard():
    db = get_db()
    rankings = db.execute("""
        SELECT u.username,
               COALESCE(sp.total, 0) - COALESCE(hc.total, 0) AS total_points
        FROM users u
        LEFT JOIN (
            SELECT solves.user_id AS uid, SUM(challenges.points) AS total
            FROM solves JOIN challenges ON solves.challenge_id = challenges.id
            GROUP BY solves.user_id
        ) sp ON sp.uid = u.id
        LEFT JOIN (
            SELECT hints_used.user_id AS uid, SUM(challenges.hint_cost) AS total
            FROM hints_used JOIN challenges ON hints_used.challenge_id = challenges.id
            GROUP BY hints_used.user_id
        ) hc ON hc.uid = u.id
        ORDER BY total_points DESC
    """).fetchall()
    db.close()

    return render_template("public_leaderboard.html", rankings=rankings)


@app.errorhandler(404)
def page_not_found(e):
    return render_template("error_404.html"), 404


@app.errorhandler(500)
def internal_error(e):
    return render_template("error_500.html"), 500


if __name__ == "__main__":
    app.run(debug=True)