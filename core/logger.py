# core/logger.py
# Logger coloré, export JSON/CSV

import logging
import json
import csv
from datetime import datetime

# Utilisez colorama pour les couleurs si installé, sinon print basique
try:
    from colorama import Fore, init
    init(autoreset=True)
    COLOR_AVAILABLE = True
except ImportError:
    COLOR_AVAILABLE = False

class PentestLogger:
    def __init__(self, log_file='pentest.log', level=logging.INFO):
        self.logger = logging.getLogger('pentest')
        self.logger.setLevel(level)

        # Handler console
        console_handler = logging.StreamHandler()
        console_handler.setLevel(level)
        console_formatter = PentestFormatter()
        console_handler.setFormatter(console_formatter)
        self.logger.addHandler(console_handler)

        # Handler fichier
        file_handler = logging.FileHandler(log_file)
        file_handler.setLevel(level)
        file_formatter = logging.Formatter('%(asctime)s - %(levelname)s - %(message)s')
        file_handler.setFormatter(file_formatter)
        self.logger.addHandler(file_handler)

        self.log_entries = []

    def log(self, level, message):
        self.logger.log(level, message)
        self.log_entries.append({
            'timestamp': datetime.now().isoformat(),
            'level': logging.getLevelName(level),
            'message': message
        })

    def info(self, message):
        self.log(logging.INFO, message)

    def warning(self, message):
        self.log(logging.WARNING, message)

    def error(self, message):
        self.log(logging.ERROR, message)

    def critical(self, message):
        self.log(logging.CRITICAL, message)

    def export_json(self, filename='logs.json'):
        with open(filename, 'w') as f:
            json.dump(self.log_entries, f, indent=4)

    def export_csv(self, filename='logs.csv'):
        with open(filename, 'w', newline='') as f:
            writer = csv.DictWriter(f, fieldnames=['timestamp', 'level', 'message'])
            writer.writeheader()
            writer.writerows(self.log_entries)

class PentestFormatter(logging.Formatter):
    def format(self, record):
        if COLOR_AVAILABLE:
            if record.levelno == logging.INFO:
                record.msg = Fore.GREEN + str(record.msg)
            elif record.levelno == logging.WARNING:
                record.msg = Fore.YELLOW + str(record.msg)
            elif record.levelno == logging.ERROR:
                record.msg = Fore.RED + str(record.msg)
            elif record.levelno == logging.CRITICAL:
                record.msg = Fore.RED + Fore.WHITE + str(record.msg)

        return super().format(record)