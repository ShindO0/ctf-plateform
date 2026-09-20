import sqlite3
import os

BASE_DIR = os.path.dirname(os.path.abspath(__file__))
DB_PATH = os.path.join(BASE_DIR, "database.db")

connexion = sqlite3.connect(DB_PATH)
curseur = connexion.cursor()

curseur.execute("""
    CREATE TABLE IF NOT EXISTS users (
        id INTEGER PRIMARY KEY AUTOINCREMENT,
        username TEXT UNIQUE NOT NULL,
        password TEXT NOT NULL
    )
""")

# Ajoute la colonne is_admin si elle n'existe pas déjà (migration simple)
try:
    curseur.execute("ALTER TABLE users ADD COLUMN is_admin INTEGER DEFAULT 0")
except sqlite3.OperationalError:
    pass  # La colonne existe déjà

curseur.execute("""
    CREATE TABLE IF NOT EXISTS challenges (
        id INTEGER PRIMARY KEY AUTOINCREMENT,
        name TEXT NOT NULL,
        description TEXT NOT NULL,
        flag TEXT NOT NULL,
        points INTEGER NOT NULL,
        difficulty TEXT NOT NULL
    )
""")

# Ajoute les colonnes indice si elles n'existent pas déjà (migration simple)
try:
    curseur.execute("ALTER TABLE challenges ADD COLUMN hint TEXT DEFAULT ''")
except sqlite3.OperationalError:
    pass

try:
    curseur.execute("ALTER TABLE challenges ADD COLUMN hint_cost INTEGER DEFAULT 0")
except sqlite3.OperationalError:
    pass

try:
    curseur.execute("ALTER TABLE challenges ADD COLUMN category TEXT DEFAULT 'Divers'")
except sqlite3.OperationalError:
    pass

try:
    curseur.execute("ALTER TABLE challenges ADD COLUMN writeup TEXT DEFAULT ''")
except sqlite3.OperationalError:
    pass

try:
    curseur.execute("ALTER TABLE challenges ADD COLUMN attachment TEXT DEFAULT ''")
except sqlite3.OperationalError:
    pass

curseur.execute("""
    CREATE TABLE IF NOT EXISTS hints_used (
        id INTEGER PRIMARY KEY AUTOINCREMENT,
        user_id INTEGER NOT NULL,
        challenge_id INTEGER NOT NULL,
        UNIQUE(user_id, challenge_id),
        FOREIGN KEY (user_id) REFERENCES users (id),
        FOREIGN KEY (challenge_id) REFERENCES challenges (id)
    )
""")

curseur.execute("""
    CREATE TABLE IF NOT EXISTS solves (
        id INTEGER PRIMARY KEY AUTOINCREMENT,
        user_id INTEGER NOT NULL,
        challenge_id INTEGER NOT NULL,
        UNIQUE(user_id, challenge_id),
        FOREIGN KEY (user_id) REFERENCES users (id),
        FOREIGN KEY (challenge_id) REFERENCES challenges (id)
    )
""")

curseur.execute("""
    CREATE TABLE IF NOT EXISTS admin_logs (
        id INTEGER PRIMARY KEY AUTOINCREMENT,
        admin_username TEXT NOT NULL,
        action TEXT NOT NULL,
        details TEXT,
        timestamp TEXT NOT NULL
    )
""")

# Deux challenges d'exemple pour tester (on en ajoutera de vrais plus tard)
curseur.execute("SELECT COUNT(*) FROM challenges")
if curseur.fetchone()[0] == 0:
    curseur.execute(
        "INSERT INTO challenges (name, description, flag, points, difficulty, category) VALUES (?, ?, ?, ?, ?, ?)",
        ("Bienvenue", "Le flag est caché dans le code source de cette page. Regarde bien (Ctrl+U).", "CTF{welcome_aboard}", 10, "Facile", "Web")
    )
    curseur.execute(
        "INSERT INTO challenges (name, description, flag, points, difficulty, category) VALUES (?, ?, ?, ?, ?, ?)",
        ("Base64", "Décode cette chaîne : Q1RGe2Jhc2U2NF9pc19ub3RfZW5jcnlwdGlvbn0=", "CTF{base64_is_not_encryption}", 20, "Facile", "Crypto")
    )

# Corrige les catégories si la base existait déjà avant l'ajout de ce champ
curseur.execute("UPDATE challenges SET category = 'Web' WHERE name = 'Bienvenue'")
curseur.execute("UPDATE challenges SET category = 'Crypto' WHERE name = 'Base64'")

# Writeups pour les challenges déjà existants
curseur.execute("UPDATE challenges SET writeup = 'Faire Ctrl+U (ou clic droit → Afficher le code source) affiche le HTML brut de la page, y compris les commentaires invisibles à l’œil comme <!-- -->.' WHERE name = 'Bienvenue' AND (writeup IS NULL OR writeup = '')")
curseur.execute("UPDATE challenges SET writeup = 'Base64 est un encodage, pas un chiffrement : aucune clé n’est nécessaire. N’importe quel site comme base64decode.org, ou la commande `echo ... | base64 -d`, suffit à le décoder.' WHERE name = 'Base64' AND (writeup IS NULL OR writeup = '')")


def ajouter_si_absent(name, description, flag, points, difficulty, category, hint="", hint_cost=0, writeup="", attachment=""):
    curseur.execute("SELECT COUNT(*) FROM challenges WHERE name = ?", (name,))
    if curseur.fetchone()[0] == 0:
        curseur.execute(
            "INSERT INTO challenges (name, description, flag, points, difficulty, category, hint, hint_cost, writeup, attachment) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?)",
            (name, description, flag, points, difficulty, category, hint, hint_cost, writeup, attachment)
        )


# 5 nouveaux challenges variés
ajouter_si_absent(
    "César en vacances",
    "Ce message a été chiffré avec un chiffrement de César (décalage de 5, y compris sur le format du flag) : HYK{hfjxfw_hnumjw}",
    "CTF{caesar_cipher}",
    15, "Facile", "Crypto",
    hint="Décale chaque lettre de 5 positions vers l'arrière dans l'alphabet.", hint_cost=5,
    writeup="Le chiffrement de César décale chaque lettre d'un nombre fixe de positions dans l'alphabet. Ici le décalage était +5 à l'encodage, donc pour décoder il faut reculer de 5 : H→C, Y→T, K→F, etc. Un site comme dcode.fr/chiffre-cesar automatise ça."
)

ajouter_si_absent(
    "En-têtes suspects",
    "Le serveur cache une information discrète dans les en-têtes HTTP de la page des challenges. Ouvre les outils de développement (F12) → onglet Network → clique sur la requête vers /challenges → regarde les 'Response Headers'.",
    "CTF{check_your_headers}",
    25, "Moyen", "Web",
    hint="Le nom de l'en-tête personnalisé commence par 'X-'.", hint_cost=10,
    writeup="Les en-têtes HTTP transportent souvent des informations invisibles à l'affichage normal de la page. Ici, le serveur Flask ajoutait un en-tête personnalisé `X-Secret-Flag` à la réponse. En vrai pentest, inspecter systématiquement les en-têtes de réponse (et de requête) est un réflexe important."
)

ajouter_si_absent(
    "Métadonnées cachées",
    "Ce texte est encodé en hexadécimal. Décode-le pour trouver le flag : 4354467B6865785F69735F656173797D",
    "CTF{hex_is_easy}",
    15, "Facile", "Forensic",
    hint="Chaque paire de caractères représente un octet ASCII. Un convertisseur hexadécimal → texte en ligne fera l'affaire.", hint_cost=5,
    writeup="Chaque paire de caractères hexadécimaux correspond à un octet, donc à un caractère ASCII (43=C, 54=T, 46=F, etc). Des sites comme rapidtables.com/convert/number/hex-to-ascii.html font la conversion instantanément."
)

ajouter_si_absent(
    "Le port qui parle",
    "Quel est le port par défaut utilisé par le protocole SSH ? Le flag suit le format CTF{port_XX} où XX est le numéro de port.",
    "CTF{port_22}",
    10, "Facile", "Réseau",
    hint="C'est le protocole utilisé pour se connecter à distance à un serveur en ligne de commande, de façon chiffrée.", hint_cost=3,
    writeup="SSH (Secure Shell) utilise par défaut le port 22. C'est un des ports les plus scannés par les attaquants, donc souvent changé en production pour limiter le bruit des tentatives automatisées."
)

ajouter_si_absent(
    "Binaire caché",
    "Ce message binaire cache le flag. Convertis-le en texte ASCII : 01000011 01010100 01000110 01111011 01100010 01101001 01101110 01100001 01110010 01111001 01011111 01101000 01101001 01100100 01100101 01111101",
    "CTF{binary_hide}",
    20, "Moyen", "Divers",
    hint="Chaque groupe de 8 chiffres (0 et 1) représente un caractère ASCII.", hint_cost=8,
    writeup="Chaque groupe de 8 bits (un octet) représente un caractère ASCII. Par exemple 01000011 = 67 en décimal = 'C'. Un convertisseur binaire → texte en ligne fait ça instantanément."
)

ajouter_si_absent(
    "Journal suspect",
    "Un serveur a été compromis. Télécharge le fichier de logs ci-dessous et retrouve la trace laissée par l'attaquant.",
    "CTF{grep_is_your_friend}",
    20, "Facile", "Forensic",
    hint="Le fichier contient beaucoup de lignes normales. Cherche une ligne qui ne ressemble pas aux autres (Ctrl+F sur 'FLAG').", hint_cost=5,
    writeup="Face à un gros fichier de logs, on ne lit pas ligne par ligne : on cherche un motif (grep, ou Ctrl+F dans un éditeur) sur des mots-clés suspects comme 'FLAG', 'ERROR' ou des adresses IP inhabituelles. Ici la ligne 'FLAG_FOUND' se distinguait du reste.",
    attachment="server_log.txt"
)

ajouter_si_absent(
    "Capture réseau",
    "Un analyste a intercepté du trafic réseau suspect. Télécharge le résumé de capture et trouve la donnée sensible qui a transité en clair.",
    "CTF{packet_sniffing_101}",
    25, "Moyen", "Réseau",
    hint="Regarde les requêtes HTTP contenant le mot 'login' — les identifiants transitent parfois en clair si le site n'utilise pas HTTPS.", hint_cost=8,
    writeup="Sans chiffrement (HTTPS/TLS), les données envoyées via HTTP classique circulent en clair sur le réseau — n'importe qui interceptant le trafic peut les lire, comme ici un mot de passe envoyé via un formulaire de connexion. C'est exactement pourquoi HTTPS est aujourd'hui la norme partout.",
    attachment="network_capture.txt"
)

ajouter_si_absent(
    "Vigenère mystérieux",
    "Ce message a été chiffré avec un chiffrement de Vigenère, clé : HACK. Décode : JTH{fpggxlrg_uly_jkjk}",
    "CTF{vigenere_key_hack}",
    35, "Difficile", "Crypto",
    hint="La clé de chiffrement est 'HACK'. Contrairement à César, le décalage change à chaque lettre selon la position dans la clé.", hint_cost=10,
    writeup="Le chiffrement de Vigenère applique un décalage différent à chaque lettre, déterminé par la lettre correspondante de la clé (répétée en boucle). Avec la clé 'HACK' (H=7, A=0, C=2, K=10), on recule chaque lettre du texte chiffré du décalage correspondant. Un outil comme dcode.fr/chiffre-vigenere automatise le calcul une fois la clé connue."
)

ajouter_si_absent(
    "ROT47",
    "Ce texte est encodé en ROT47 (une variante de ROT13 qui inclut aussi chiffres et symboles) : r%uLC@Ecf0:D07F?N",
    "CTF{rot47_is_fun}",
    20, "Moyen", "Crypto",
    hint="ROT47 décale chaque caractère ASCII imprimable (33 à 126) de 47 positions. Un décodeur ROT47 en ligne fait le travail.", hint_cost=8,
    writeup="ROT47 fonctionne comme ROT13 mais sur une plage plus large de caractères ASCII imprimables (33-126), ce qui permet d'inclure aussi les chiffres et symboles, pas seulement les lettres. Un site comme rot47.net décode instantanément."
)

ajouter_si_absent(
    "XOR à sens unique",
    "Ce flag a été XORé avec un seul octet répété, puis converti en hexadécimal : 697e6c5152455875435975584f5c4f58594348464f57",
    "CTF{xor_is_reversible}",
    35, "Difficile", "Forensic",
    hint="Le flag en clair commence forcément par 'CTF{'. XORe le premier octet du hex avec le caractère 'C' pour retrouver la clé utilisée, puis applique-la à tout le reste.", hint_cost=12,
    writeup="Le XOR à clé unique répète un seul octet sur tout le message. Comme on connaît le début probable du texte clair ('CTF{'), on peut XORer le premier octet chiffré avec 'C' (0x43) pour retrouver la clé (ici 0x2A), puis l'appliquer à tout le reste : c'est une attaque classique par texte clair connu (known-plaintext attack)."
)

ajouter_si_absent(
    "Cookie de session",
    "Le serveur dépose un cookie discret quand tu charges la page des challenges. Ouvre les outils de développement (F12) → onglet Application (ou Storage) → Cookies, et regarde s'il y en a un avec une valeur suspecte.",
    "CTF{cookie_monster}",
    30, "Difficile", "Web",
    hint="Le cookie s'appelle 'debug_session'. Sa valeur est encodée dans un format que tu as déjà croisé plusieurs fois dans cette plateforme.", hint_cost=10,
    writeup="Les cookies peuvent contenir n'importe quelle donnée déposée par le serveur, y compris des informations qui ne devraient jamais s'y trouver. Ici, un cookie nommé 'debug_session' contenait le flag encodé en Base64 — une mauvaise pratique bien réelle : ne jamais stocker de secrets, même encodés (l'encodage n'est pas du chiffrement), dans un cookie lisible côté client."
)

ajouter_si_absent(
    "Texte invisible",
    "Ce fichier a l'air vide... vraiment ? Télécharge-le et regarde de plus près.",
    "CTF{whitespace_hide}",
    15, "Facile", "Stéganographie",
    hint="Ouvre le fichier dans un éditeur de texte et sélectionne tout le contenu (Ctrl+A), ou fais défiler très loin vers la droite.", hint_cost=5,
    writeup="Une technique simple de dissimulation consiste à écrire du texte après une très longue série d'espaces, invisible à l'écran sans défilement horizontal. Sélectionner tout le contenu (Ctrl+A) ou activer le retour à la ligne automatique dans l'éditeur révèle immédiatement le texte caché.",
    attachment="hidden_text.txt"
)

connexion.commit()
connexion.close()

print("Base de données créée avec succès (database.db)")