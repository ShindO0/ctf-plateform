import sqlite3
import sys

if len(sys.argv) != 2:
    print("Utilisation : python promote_admin.py <nom_utilisateur>")
    sys.exit(1)

username = sys.argv[1]

connexion = sqlite3.connect("database.db")
curseur = connexion.cursor()

curseur.execute("UPDATE users SET is_admin = 1 WHERE username = ?", (username,))
connexion.commit()

if curseur.rowcount == 0:
    print(f"Aucun utilisateur nommé '{username}' trouvé.")
else:
    print(f"'{username}' est maintenant administrateur.")

connexion.close()