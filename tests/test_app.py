"""
Suite de tests automatisés pour la plateforme CTF.
Lancer avec : pytest -v (depuis la racine du projet)

Chaque test tourne sur une base de données SQLite temporaire, séparée de
database.db — aucun risque d'abîmer les vraies données pendant les tests.
"""
import os
import sys
import sqlite3
import tempfile
import pyotp
import pytest

sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))
import app as flask_app_module

TEST_INVITE_CODE = "test-invite-code"


@pytest.fixture
def client():
    db_fd, db_path = tempfile.mkstemp()

    # Redirige l'appli vers la base de test, et réinitialise les compteurs anti brute-force
    flask_app_module.DB_PATH = db_path
    flask_app_module.REGISTRATION_CODE = TEST_INVITE_CODE
    flask_app_module.app.config["TESTING"] = True
    flask_app_module.app.config["WTF_CSRF_ENABLED"] = False
    flask_app_module.login_attempts.clear()
    flask_app_module.flag_attempts.clear()
    flask_app_module.register_attempts.clear()
    flask_app_module.twofa_attempts.clear()

    conn = sqlite3.connect(db_path)
    conn.executescript("""
        CREATE TABLE users (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            username TEXT UNIQUE NOT NULL,
            password TEXT NOT NULL,
            is_admin INTEGER DEFAULT 0,
            totp_secret TEXT DEFAULT '',
            totp_enabled INTEGER DEFAULT 0,
            api_key TEXT DEFAULT ''
        );
        CREATE TABLE challenges (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            name TEXT NOT NULL,
            description TEXT NOT NULL,
            flag TEXT NOT NULL,
            points INTEGER NOT NULL,
            difficulty TEXT NOT NULL,
            category TEXT DEFAULT 'Divers',
            hint TEXT DEFAULT '',
            hint_cost INTEGER DEFAULT 0,
            writeup TEXT DEFAULT '',
            attachment TEXT DEFAULT ''
        );
        CREATE TABLE solves (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            user_id INTEGER NOT NULL,
            challenge_id INTEGER NOT NULL,
            UNIQUE(user_id, challenge_id)
        );
        CREATE TABLE hints_used (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            user_id INTEGER NOT NULL,
            challenge_id INTEGER NOT NULL,
            UNIQUE(user_id, challenge_id)
        );
        CREATE TABLE admin_logs (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            admin_username TEXT NOT NULL,
            action TEXT NOT NULL,
            details TEXT,
            timestamp TEXT NOT NULL
        );
    """)
    conn.commit()
    conn.close()

    with flask_app_module.app.test_client() as test_client:
        yield test_client

    os.close(db_fd)
    os.unlink(db_path)


def register(client, username="alice", password="motdepasse", code=TEST_INVITE_CODE):
    return client.post("/register", data={
        "username": username, "password": password, "invite_code": code
    }, follow_redirects=True)


def login(client, username="alice", password="motdepasse"):
    return client.post("/login", data={"username": username, "password": password})


# ---------- Inscription ----------

def test_register_success(client):
    resp = register(client)
    assert resp.status_code == 200
    assert "succ\xe8s".encode() in resp.data or b"succ" in resp.data


def test_register_wrong_invite_code(client):
    resp = register(client, code="mauvais-code")
    assert "incorrect".encode() in resp.data


def test_register_duplicate_username(client):
    register(client, username="bob")
    resp = register(client, username="bob")
    assert "d\xe9j\xe0 pris".encode() in resp.data or b"pris" in resp.data


def test_register_short_password(client):
    resp = register(client, username="carol", password="ab")
    assert b"caract" in resp.data


# ---------- Connexion ----------

def test_login_success_redirects_to_dashboard(client):
    register(client, username="dave")
    resp = login(client, username="dave")
    assert resp.status_code == 302
    assert "/dashboard" in resp.headers["Location"]


def test_login_wrong_password(client):
    register(client, username="erin")
    resp = login(client, username="erin", password="mauvais")
    assert b"incorrect" in resp.data


def test_login_lockout_after_5_failures(client):
    register(client, username="frank")
    for _ in range(5):
        login(client, username="frank", password="mauvais")
    resp = login(client, username="frank", password="motdepasse")  # même le bon mdp est bloqué
    assert "tentatives".encode() in resp.data


# ---------- Contrôle d'accès ----------

def test_dashboard_requires_login(client):
    resp = client.get("/dashboard")
    assert resp.status_code == 302


def test_admin_panel_requires_admin(client):
    register(client, username="greg")
    login(client, username="greg")
    resp = client.get("/admin")
    assert resp.status_code == 302  # redirigé, pas d'accès


# ---------- Soumission de flags ----------

def test_flag_submission_correct_and_incorrect(client):
    register(client, username="hana")
    login(client, username="hana")

    conn = sqlite3.connect(flask_app_module.DB_PATH)
    conn.execute(
        "INSERT INTO challenges (name, description, flag, points, difficulty, category) VALUES (?, ?, ?, ?, ?, ?)",
        ("Test Challenge", "desc", "CTF{test_flag}", 10, "Facile", "Divers")
    )
    conn.commit()
    conn.close()

    resp_wrong = client.post("/submit/1", data={"flag": "CTF{mauvais}"}, follow_redirects=True)
    assert resp_wrong.status_code == 200

    resp_correct = client.post("/submit/1", data={"flag": "CTF{test_flag}"}, follow_redirects=True)
    assert resp_correct.status_code == 200

    conn = sqlite3.connect(flask_app_module.DB_PATH)
    count = conn.execute("SELECT COUNT(*) FROM solves").fetchone()[0]
    conn.close()
    assert count == 1


# ---------- API ----------

def test_api_requires_auth(client):
    resp = client.get("/api/challenges")
    assert resp.status_code == 401


def test_api_key_authentication(client):
    register(client, username="ivan")
    login(client, username="ivan")

    conn = sqlite3.connect(flask_app_module.DB_PATH)
    conn.execute("UPDATE users SET api_key = ? WHERE username = ?", ("test-api-key-123", "ivan"))
    conn.commit()
    conn.close()

    client.get("/logout")

    resp = client.get("/api/me", headers={"X-API-Key": "test-api-key-123"})
    assert resp.status_code == 200
    assert resp.get_json()["username"] == "ivan"


# ---------- 2FA ----------

def test_login_with_2fa_requires_code(client):
    register(client, username="julia")

    secret = pyotp.random_base32()
    conn = sqlite3.connect(flask_app_module.DB_PATH)
    conn.execute(
        "UPDATE users SET totp_secret = ?, totp_enabled = 1 WHERE username = ?",
        (secret, "julia")
    )
    conn.commit()
    conn.close()

    resp = login(client, username="julia")
    assert resp.status_code == 302
    assert "/verify-2fa" in resp.headers["Location"]

    valid_code = pyotp.TOTP(secret).now()
    resp2 = client.post("/verify-2fa", data={"code": valid_code}, follow_redirects=False)
    assert resp2.status_code == 302
    assert "/dashboard" in resp2.headers["Location"]