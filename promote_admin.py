import sqlite3
import sys
import os

BASE_DIR = os.path.dirname(os.path.abspath(__file__))
DB_PATH = os.path.join(BASE_DIR, "database.db")

if len(sys.argv) < 2:
    print("Utilisation : python promote_admin.py <nom_utilisateur> [off]")
    print("  Sans 'off' : donne les droits admin")
    print("  Avec 'off' : retire les droits admin")
    sys.exit(1)

username = sys.argv[1]
remove = len(sys.argv) > 2 and sys.argv[2].lower() == "off"
new_status = 0 if remove else 1

connexion = sqlite3.connect(DB_PATH)
curseur = connexion.cursor()

curseur.execute("UPDATE users SET is_admin = ? WHERE username = ?", (new_status, username))
connexion.commit()

if curseur.rowcount == 0:
    print(f"Aucun utilisateur nommé '{username}' trouvé.")
elif remove:
    print(f"'{username}' n'est plus administrateur.")
else:
    print(f"'{username}' est maintenant administrateur.")

connexion.close()