# core/utils.py

def read_wordlist(path):
    """Lit un fichier wordlist et retourne une liste de mots de passe"""
    with open(path, 'r', encoding='utf-8', errors='ignore') as f:
        return [line.strip() for line in f if line.strip()]

def split_targets(targets_str):
    """Transforme une chaîne de cibles séparées par des virgules en liste"""
    return [t.strip() for t in targets_str.split(",") if t.strip()]
