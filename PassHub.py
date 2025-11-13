import sys
import sqlite3
import hashlib
import secrets
import string
import os
import base64
import time
import shutil
import json
import requests
from datetime import datetime
from cryptography.fernet import Fernet
from PyQt6.QtWidgets import (QApplication, QMainWindow, QWidget, QVBoxLayout,
                             QHBoxLayout, QPushButton, QTabWidget, QLabel,
                             QLineEdit, QTextEdit, QTableWidget, QTableWidgetItem,
                             QMessageBox, QDialog, QDialogButtonBox, QFormLayout,
                             QSpinBox, QCheckBox, QHeaderView, QMenu)
from PyQt6.QtCore import Qt, QTimer
from PyQt6.QtGui import QFont, QAction, QCursor


class YandexDiskBackup:
    """Класс для работы с Яндекс.Диском"""

    def __init__(self, token=None):
        self.token = token
        self.base_url = "https://cloud-api.yandex.net/v1/disk/resources"
        self.headers = {
            'Authorization': f'OAuth {token}',
            'Content-Type': 'application/json'
        } if token else {}

    def check_token_valid(self):
        """Проверка валидности токена"""
        if not self.token:
            return False

        try:
            response = requests.get(
                "https://cloud-api.yandex.net/v1/disk",
                headers=self.headers,
                timeout=10
            )
            return response.status_code == 200
        except Exception as e:
            print(f"Ошибка проверки токена: {e}")
            return False

    def create_folder(self, folder_name="PassHub_Backups"):
        """Создание папки на Яндекс.Диске"""
        try:
            url = f"{self.base_url}"
            params = {'path': folder_name}
            response = requests.put(url, headers=self.headers, params=params, timeout=10)
            # 409 - папка уже существует
            return response.status_code in [200, 201, 409]
        except Exception as e:
            print(f"Ошибка создания папки: {e}")
            return False

    def upload_file(self, file_path, remote_folder="PassHub_Backups"):
        """Загрузка файла на Яндекс.Диск"""
        try:
            file_name = os.path.basename(file_path)
            remote_path = f"{remote_folder}/{file_name}"

            # Получаем URL для загрузки
            url = f"{self.base_url}/upload"
            params = {'path': remote_path, 'overwrite': 'true'}

            response = requests.get(url, headers=self.headers, params=params, timeout=10)
            if response.status_code != 200:
                print(f"Ошибка получения URL для загрузки: {response.status_code}")
                return False

            upload_url = response.json()['href']

            # Загружаем файл напрямую
            with open(file_path, 'rb') as f:
                upload_response = requests.put(upload_url, data=f, timeout=30)

            return upload_response.status_code in [200, 201]

        except Exception as e:
            print(f"Ошибка загрузки файла: {e}")
            return False

    def get_backup_list(self, folder="PassHub_Backups"):
        """Получение списка бэкапов"""
        try:
            url = f"{self.base_url}"
            params = {'path': folder, 'limit': 50}

            response = requests.get(url, headers=self.headers, params=params, timeout=10)
            if response.status_code != 200:
                print(f"Ошибка получения списка: {response.status_code}")
                return []

            items = response.json().get('_embedded', {}).get('items', [])
            backups = []

            for item in items:
                if item['name'].endswith('.backup'):
                    backups.append({
                        'name': item['name'],
                        'size': item['size'],
                        'modified': item['modified']
                    })

            return sorted(backups, key=lambda x: x['modified'], reverse=True)

        except Exception as e:
            print(f"Ошибка получения списка бэкапов: {e}")
            return []

    def download_file(self, remote_file, local_path, folder="PassHub_Backups"):
        """Скачивание файла с Яндекс.Диска"""
        try:
            remote_path = f"{folder}/{remote_file}"
            url = f"{self.base_url}/download"
            params = {'path': remote_path}

            response = requests.get(url, headers=self.headers, params=params, timeout=10)
            if response.status_code != 200:
                print(f"Ошибка получения URL для скачивания: {response.status_code}")
                return False

            download_url = response.json()['href']
            file_response = requests.get(download_url, timeout=30)

            with open(local_path, 'wb') as f:
                f.write(file_response.content)

            return True

        except Exception as e:
            print(f"Ошибка скачивания файла: {e}")
            return False


class YandexDiskSetupDialog(QDialog):
    """Диалог настройки Яндекс.Диска"""

    def __init__(self, parent=None, current_token=None):
        super().__init__(parent)
        self.setWindowTitle("Настройка Яндекс.Диска")
        self.setModal(True)
        self.setFixedSize(500, 450)
        self.token = current_token
        self.init_ui()

    def init_ui(self):
        layout = QVBoxLayout(self)

        # Инструкция
        instruction = QLabel(
            "<b>Для использования резервного копирования на Яндекс.Диске:</b><br><br>"
            "1. Перейдите по ссылке: <a href='https://yandex.ru/dev/disk/poligon/'>https://yandex.ru/dev/disk/poligon/</a><br>"
            "2. Авторизуйтесь под своим аккаунтом<br>"
            "3. Нажмите 'Получить OAuth-токен'<br>"
            "4. Скопируйте полученный токен в поле ниже<br><br>"
            "<i>Токен будет сохранен локально и использоваться для автоматического бэкапа.</i>"
        )
        instruction.setWordWrap(True)
        instruction.setOpenExternalLinks(True)
        layout.addWidget(instruction)

        # Поле для токена
        token_layout = QFormLayout()
        self.token_input = QLineEdit()
        if self.token:
            self.token_input.setText(self.token)
        self.token_input.setPlaceholderText("Вставьте OAuth-токен Яндекс.Диска")
        token_layout.addRow("OAuth-токен:", self.token_input)
        layout.addLayout(token_layout)

        # Кнопка проверки
        self.test_btn = QPushButton("Проверить подключение")
        self.test_btn.clicked.connect(self.test_connection)
        layout.addWidget(self.test_btn)

        # Статус
        self.status_label = QLabel("")
        self.status_label.setWordWrap(True)
        layout.addWidget(self.status_label)

        # Кнопки
        buttons = QDialogButtonBox(
            QDialogButtonBox.StandardButton.Ok |
            QDialogButtonBox.StandardButton.Cancel
        )
        buttons.accepted.connect(self.verify_and_accept)
        buttons.rejected.connect(self.reject)
        layout.addWidget(buttons)

    def test_connection(self):
        """Проверка подключения к Яндекс.Диску"""
        token = self.token_input.text().strip()
        if not token:
            self.status_label.setText("Введите токен для проверки")
            self.status_label.setStyleSheet("color: red;")
            return

        self.status_label.setText("Проверка соединения...")
        self.status_label.setStyleSheet("color: orange;")
        QApplication.processEvents()

        ydisk = YandexDiskBackup(token)
        if ydisk.check_token_valid():
            self.status_label.setText("Подключение успешно! Токен действителен.")
            self.status_label.setStyleSheet("color: green;")
        else:
            self.status_label.setText("Неверный токен или проблемы с подключением к Яндекс.Диску")
            self.status_label.setStyleSheet("color: red;")

    def verify_and_accept(self):
        """Проверка и принятие токена"""
        token = self.token_input.text().strip()
        if not token:
            QMessageBox.warning(self, "Ошибка", "Введите OAuth-токен!")
            return

        ydisk = YandexDiskBackup(token)
        if ydisk.check_token_valid():
            self.token = token
            self.accept()
        else:
            reply = QMessageBox.question(
                self,
                "Неверный токен",
                "Токен не прошел проверку. Сохранить его все равно?",
                QMessageBox.StandardButton.Yes | QMessageBox.StandardButton.No
            )
            if reply == QMessageBox.StandardButton.Yes:
                self.token = token
                self.accept()


class BackupRestoreDialog(QDialog):
    """Диалог восстановления из бэкапа"""

    def __init__(self, parent=None, ydisk=None):
        super().__init__(parent)
        self.setWindowTitle("Восстановление из бэкапа")
        self.setModal(True)
        self.setFixedSize(700, 450)
        self.ydisk = ydisk
        self.selected_backup = None
        self.init_ui()
        self.load_backups()

    def init_ui(self):
        layout = QVBoxLayout(self)

        # Список бэкапов
        layout.addWidget(QLabel("Доступные резервные копии на Яндекс.Диске:"))
        self.backups_list = QTableWidget()
        self.backups_list.setColumnCount(3)
        self.backups_list.setHorizontalHeaderLabels(["Имя файла", "Размер", "Дата изменения"])
        self.backups_list.setSelectionBehavior(QTableWidget.SelectionBehavior.SelectRows)
        self.backups_list.setSelectionMode(QTableWidget.SelectionMode.SingleSelection)
        self.backups_list.horizontalHeader().setSectionResizeMode(QHeaderView.ResizeMode.Stretch)
        layout.addWidget(self.backups_list)

        # Кнопка обновления
        refresh_btn = QPushButton("Обновить список")
        refresh_btn.clicked.connect(self.load_backups)
        layout.addWidget(refresh_btn)

        # Кнопки
        buttons = QDialogButtonBox(
            QDialogButtonBox.StandardButton.Ok |
            QDialogButtonBox.StandardButton.Cancel
        )
        buttons.accepted.connect(self.accept_selection)
        buttons.rejected.connect(self.reject)
        layout.addWidget(buttons)

    def load_backups(self):
        """Загрузка списка бэкапов"""
        if not self.ydisk:
            QMessageBox.warning(self, "Ошибка", "Не настроено подключение к Яндекс.Диску!")
            return

        backups = self.ydisk.get_backup_list()
        self.backups_list.setRowCount(len(backups))

        if len(backups) == 0:
            QMessageBox.information(self, "Информация", "Резервные копии на Яндекс.Диске не найдены.")

        for row, backup in enumerate(backups):
            self.backups_list.setItem(row, 0, QTableWidgetItem(backup['name']))
            self.backups_list.setItem(row, 1, QTableWidgetItem(self.format_size(backup['size'])))

            # Форматируем дату
            try:
                date_obj = datetime.fromisoformat(backup['modified'].replace('Z', '+00:00'))
                formatted_date = date_obj.strftime('%d.%m.%Y %H:%M:%S')
            except:
                formatted_date = backup['modified']

            self.backups_list.setItem(row, 2, QTableWidgetItem(formatted_date))

    def format_size(self, size_bytes):
        """Форматирование размера файла"""
        for unit in ['B', 'KB', 'MB', 'GB']:
            if size_bytes < 1024.0:
                return f"{size_bytes:.1f} {unit}"
            size_bytes /= 1024.0
        return f"{size_bytes:.1f} TB"

    def accept_selection(self):
        """Принятие выбора бэкапа"""
        current_row = self.backups_list.currentRow()
        if current_row == -1:
            QMessageBox.warning(self, "Ошибка", "Выберите бэкап для восстановления!")
            return

        backup_name = self.backups_list.item(current_row, 0).text()

        reply = QMessageBox.question(
            self,
            "Подтверждение",
            f"Восстановить данные из бэкапа '{backup_name}'?\n\n"
            "ВНИМАНИЕ: Текущие данные будут ЗАМЕНЕНЫ!\n"
            "Рекомендуется создать резервную копию текущих данных перед восстановлением.",
            QMessageBox.StandardButton.Yes | QMessageBox.StandardButton.No
        )

        if reply == QMessageBox.StandardButton.Yes:
            self.selected_backup = backup_name
            self.accept()


class LoginDialog(QDialog):
    """Диалог входа в систему"""

    def __init__(self, parent=None):
        super().__init__(parent)
        self.setWindowTitle("Вход в PassHub")
        self.setModal(True)
        self.setFixedSize(350, 150)
        self.init_ui()

    def init_ui(self):
        layout = QVBoxLayout(self)

        layout.addWidget(QLabel("<h3>Добро пожаловать в PassHub!</h3>"))
        layout.addWidget(QLabel("Введите мастер-пароль:"))

        self.password_input = QLineEdit()
        self.password_input.setEchoMode(QLineEdit.EchoMode.Password)
        self.password_input.setPlaceholderText("Мастер-пароль")
        layout.addWidget(self.password_input)

        buttons = QDialogButtonBox(
            QDialogButtonBox.StandardButton.Ok |
            QDialogButtonBox.StandardButton.Cancel
        )
        buttons.accepted.connect(self.accept)
        buttons.rejected.connect(self.reject)
        layout.addWidget(buttons)


class SetupMasterPasswordDialog(QDialog):
    """Диалог установки мастер-пароля"""

    def __init__(self, parent=None):
        super().__init__(parent)
        self.setWindowTitle("Установка мастер-пароля")
        self.setModal(True)
        self.setFixedSize(400, 180)
        self.init_ui()

    def init_ui(self):
        layout = QFormLayout(self)

        layout.addRow(QLabel("<h3>Создание мастер-пароля</h3>"))

        self.password_input = QLineEdit()
        self.password_input.setEchoMode(QLineEdit.EchoMode.Password)
        self.password_input.setPlaceholderText("Минимум 4 символа")

        self.confirm_input = QLineEdit()
        self.confirm_input.setEchoMode(QLineEdit.EchoMode.Password)
        self.confirm_input.setPlaceholderText("Повторите пароль")

        layout.addRow("Мастер-пароль:", self.password_input)
        layout.addRow("Подтверждение:", self.confirm_input)

        buttons = QDialogButtonBox(
            QDialogButtonBox.StandardButton.Ok |
            QDialogButtonBox.StandardButton.Cancel
        )
        buttons.accepted.connect(self.verify_passwords)
        buttons.rejected.connect(self.reject)
        layout.addRow(buttons)

    def verify_passwords(self):
        if self.password_input.text() != self.confirm_input.text():
            QMessageBox.warning(self, "Ошибка", "Пароли не совпадают!")
            return

        if len(self.password_input.text()) < 4:
            QMessageBox.warning(self, "Ошибка", "Пароль должен быть не менее 4 символов!")
            return

        self.accept()


class AddPasswordDialog(QDialog):
    """Диалог добавления/редактирования пароля"""

    def __init__(self, parent=None, edit_mode=False, data=None):
        super().__init__(parent)
        self.edit_mode = edit_mode
        self.original_service = None
        
        if edit_mode:
            self.setWindowTitle("Редактировать пароль")
            self.original_service = data.get('service', '') if data else None
        else:
            self.setWindowTitle("Добавить пароль")
            
        self.setModal(True)
        self.setFixedSize(450, 350)
        self.init_ui(data)

    def init_ui(self, data=None):
        layout = QFormLayout(self)

        self.service_input = QLineEdit()
        self.service_input.setPlaceholderText("Например: Gmail, VK, GitHub")

        self.username_input = QLineEdit()
        self.username_input.setPlaceholderText("Логин или email")

        self.password_input = QLineEdit()
        self.password_input.setEchoMode(QLineEdit.EchoMode.Password)
        self.password_input.setPlaceholderText("Пароль для сервиса")

        # Кнопка показать/скрыть пароль
        password_layout = QHBoxLayout()
        password_layout.addWidget(self.password_input)
        
        self.show_password_btn = QPushButton("👁")
        self.show_password_btn.setFixedWidth(40)
        self.show_password_btn.setToolTip("Показать/скрыть пароль")
        self.show_password_btn.clicked.connect(self.toggle_password_visibility)
        password_layout.addWidget(self.show_password_btn)

        self.notes_input = QTextEdit()
        self.notes_input.setMaximumHeight(100)
        self.notes_input.setPlaceholderText("Дополнительная информация (необязательно)")

        # Если режим редактирования, заполняем поля
        if self.edit_mode and data:
            self.service_input.setText(data.get('service', ''))
            self.username_input.setText(data.get('username', ''))
            self.password_input.setText(data.get('password', ''))
            self.notes_input.setPlainText(data.get('notes', ''))
            
            # В режиме редактирования делаем поле "Сервис" только для чтения
            self.service_input.setReadOnly(True)
            self.service_input.setStyleSheet("background-color: #f0f0f0;")

        layout.addRow("Сервис *:", self.service_input)
        layout.addRow("Логин *:", self.username_input)
        layout.addRow("Пароль *:", password_layout)
        layout.addRow("Заметки:", self.notes_input)

        if self.edit_mode:
            note = QLabel("<i>Примечание: название сервиса нельзя изменить</i>")
            note.setStyleSheet("color: #666; font-size: 10px;")
            layout.addRow("", note)

        buttons = QDialogButtonBox(
            QDialogButtonBox.StandardButton.Ok |
            QDialogButtonBox.StandardButton.Cancel
        )
        buttons.accepted.connect(self.accept)
        buttons.rejected.connect(self.reject)
        layout.addRow(buttons)

    def toggle_password_visibility(self):
        """Переключение видимости пароля"""
        if self.password_input.echoMode() == QLineEdit.EchoMode.Password:
            self.password_input.setEchoMode(QLineEdit.EchoMode.Normal)
            self.show_password_btn.setText("🔒")
        else:
            self.password_input.setEchoMode(QLineEdit.EchoMode.Password)
            self.show_password_btn.setText("👁")

    def get_data(self):
        return {
            'service': self.service_input.text().strip(),
            'username': self.username_input.text().strip(),
            'password': self.password_input.text(),
            'notes': self.notes_input.toPlainText().strip()
        }


class PanicButtonDialog(QDialog):
    """Диалог подтверждения паники"""

    def __init__(self, parent=None):
        super().__init__(parent)
        self.setWindowTitle("Активация кнопки паники")
        self.setModal(True)
        self.setFixedSize(400, 150)
        self.init_ui()

    def init_ui(self):
        layout = QVBoxLayout(self)

        warning = QLabel("<b>ВНИМАНИЕ!</b><br>Введите код подтверждения для активации режима паники:")
        warning.setWordWrap(True)
        layout.addWidget(warning)

        self.code_input = QLineEdit()
        self.code_input.setPlaceholderText("Введите 1234 для активации")
        self.code_input.setEchoMode(QLineEdit.EchoMode.Password)
        layout.addWidget(self.code_input)

        buttons = QDialogButtonBox(
            QDialogButtonBox.StandardButton.Ok |
            QDialogButtonBox.StandardButton.Cancel
        )
        buttons.accepted.connect(self.verify_code)
        buttons.rejected.connect(self.reject)
        layout.addWidget(buttons)

    def verify_code(self):
        if self.code_input.text() == "1234":
            self.accept()
        else:
            QMessageBox.warning(self, "Ошибка", "Неверный код подтверждения!")
            self.code_input.clear()


class PasswordManager(QMainWindow):
    """Главное окно менеджера паролей"""

    def __init__(self):
        super().__init__()
        print("=== ЗАПУСК PASSHUB ===")

        # Инициализация переменных
        self.db_conn = None
        self.cipher_suite = None
        self.master_password_hash = None
        self.salt = None
        self.is_authenticated = False
        self.current_master_password = None
        self.panic_activated = False
        self.panic_timer = QTimer()
        self.panic_timer.timeout.connect(self.emergency_cleanup)
        self.countdown = 0

        # Яндекс.Диск
        self.ydisk = None
        self.load_ydisk_token()

        # Инициализация БД
        self.init_database()

        # Аутентификация
        if not self.is_master_password_set():
            print("Первый запуск - установка мастер-пароля...")
            self.setup_master_password()
        else:
            print("Аутентификация пользователя...")
            self.authenticate_user()

        # Инициализация интерфейса
        if self.is_authenticated:
            print("Инициализация UI...")
            self.init_ui()
            self.setWindowTitle("PassHub - Менеджер паролей")
            self.setGeometry(300, 200, 900, 650)
            self.init_encryption()
            print("=== PASSHUB УСПЕШНО ЗАПУЩЕН ===")

    def load_ydisk_token(self):
        """Загрузка токена Яндекс.Диска"""
        try:
            token_file = 'ydisk_token.txt'
            if os.path.exists(token_file):
                with open(token_file, 'r', encoding='utf-8') as f:
                    token = f.read().strip()
                    if token:
                        self.ydisk = YandexDiskBackup(token)
                        if self.ydisk.check_token_valid():
                            print("Яндекс.Диск подключен")
                        else:
                            print("Токен Яндекс.Диска невалиден")
                            self.ydisk = None
        except Exception as e:
            print(f"Ошибка загрузки токена: {e}")

    def save_ydisk_token(self, token):
        """Сохранение токена Яндекс.Диска"""
        try:
            with open('ydisk_token.txt', 'w', encoding='utf-8') as f:
                f.write(token)
            self.ydisk = YandexDiskBackup(token)
            print("Токен Яндекс.Диска сохранен")
        except Exception as e:
            print(f"Ошибка сохранения токена: {e}")

    def init_database(self):
        """Инициализация базы данных"""
        try:
            self.db_conn = sqlite3.connect('passhub.db', check_same_thread=False)
            cursor = self.db_conn.cursor()

            # Таблица мастер-пароля
            cursor.execute('''
                CREATE TABLE IF NOT EXISTS master_password (
                    id INTEGER PRIMARY KEY,
                    password_hash TEXT NOT NULL,
                    salt TEXT NOT NULL
                )
            ''')

            # Таблица паролей
            cursor.execute('''
                CREATE TABLE IF NOT EXISTS passwords (
                    id INTEGER PRIMARY KEY AUTOINCREMENT,
                    service TEXT NOT NULL,
                    username TEXT NOT NULL,
                    password_encrypted TEXT NOT NULL,
                    notes_encrypted TEXT,
                    created_at DATETIME DEFAULT CURRENT_TIMESTAMP
                )
            ''')

            self.db_conn.commit()
            print("База данных инициализирована")

        except Exception as e:
            print(f"Ошибка БД: {e}")

    def is_master_password_set(self):
        """Проверка наличия мастер-пароля"""
        try:
            cursor = self.db_conn.cursor()
            cursor.execute("SELECT COUNT(*) FROM master_password")
            return cursor.fetchone()[0] > 0
        except:
            return False

    def setup_master_password(self):
        """Установка мастер-пароля"""
        dialog = SetupMasterPasswordDialog()
        if dialog.exec() == QDialog.DialogCode.Accepted:
            password = dialog.password_input.text()
            self.current_master_password = password
            self.save_master_password(password)
            self.is_authenticated = True
            QMessageBox.information(None, "Успех", "Мастер-пароль успешно установлен!")
        else:
            sys.exit(0)

    def authenticate_user(self):
        """Аутентификация"""
        dialog = LoginDialog()
        attempts = 0

        while attempts < 3:
            if dialog.exec() == QDialog.DialogCode.Accepted:
                password = dialog.password_input.text()
                if self.verify_master_password(password):
                    self.current_master_password = password
                    self.is_authenticated = True
                    return
                else:
                    attempts += 1
                    QMessageBox.warning(
                        None,
                        "Ошибка",
                        f"Неверный пароль!\nПопыток осталось: {3 - attempts}"
                    )
            else:
                sys.exit(0)

        QMessageBox.critical(None, "Ошибка", "Превышено число попыток входа!")
        sys.exit(0)

    def save_master_password(self, password):
        """Сохранение мастер-пароля"""
        try:
            self.salt = os.urandom(32)
            password_hash = hashlib.pbkdf2_hmac(
                'sha256',
                password.encode('utf-8'),
                self.salt,
                100000
            )

            cursor = self.db_conn.cursor()
            cursor.execute(
                "INSERT OR REPLACE INTO master_password (id, password_hash, salt) VALUES (1, ?, ?)",
                (password_hash.hex(), self.salt.hex())
            )
            self.db_conn.commit()
            print("Мастер-пароль сохранен")

        except Exception as e:
            print(f"Ошибка сохранения пароля: {e}")

    def verify_master_password(self, password):
        """Проверка мастер-пароля"""
        try:
            cursor = self.db_conn.cursor()
            cursor.execute("SELECT password_hash, salt FROM master_password WHERE id = 1")
            result = cursor.fetchone()

            if not result:
                return False

            stored_hash_hex, salt_hex = result
            salt = bytes.fromhex(salt_hex)

            input_hash = hashlib.pbkdf2_hmac(
                'sha256',
                password.encode('utf-8'),
                salt,
                100000
            )

            return input_hash.hex() == stored_hash_hex

        except Exception as e:
            print(f"Ошибка проверки пароля: {e}")
            return False

    def init_encryption(self):
        """Инициализация шифрования"""
        try:
            if not self.current_master_password:
                print("Мастер-пароль не установлен")
                return

            # Генерируем ключ из пароля
            key = hashlib.sha256(self.current_master_password.encode()).digest()
            key_32 = key[:32]
            fernet_key = base64.urlsafe_b64encode(key_32)
            self.cipher_suite = Fernet(fernet_key)

            print("Шифрование инициализировано")

        except Exception as e:
            print(f"Ошибка шифрования: {e}")
            self.cipher_suite = None

    def encrypt_data(self, data):
        """Шифрование данных"""
        if not self.cipher_suite or not data:
            return data

        try:
            encrypted = self.cipher_suite.encrypt(data.encode())
            return base64.urlsafe_b64encode(encrypted).decode()
        except Exception as e:
            print(f"Ошибка шифрования: {e}")
            return data

    def decrypt_data(self, encrypted_data):
        """Дешифрование данных"""
        if not self.cipher_suite or not encrypted_data:
            return encrypted_data

        try:
            encrypted_bytes = base64.urlsafe_b64decode(encrypted_data.encode())
            decrypted = self.cipher_suite.decrypt(encrypted_bytes)
            return decrypted.decode()
        except Exception as e:
            print(f"Ошибка дешифрования: {e}")
            return "*** ОШИБКА ***"

    def init_ui(self):
        """Инициализация интерфейса"""
        if not self.is_authenticated:
            return

        central_widget = QWidget()
        self.setCentralWidget(central_widget)
        main_layout = QVBoxLayout(central_widget)

        tabs = QTabWidget()
        tabs.addTab(self.create_passwords_tab(), "Мои пароли")
        tabs.addTab(self.create_generator_tab(), "Генератор")
        tabs.addTab(self.create_settings_tab(), "Настройки")

        main_layout.addWidget(tabs)

    def create_passwords_tab(self):
        """Вкладка паролей"""
        widget = QWidget()
        layout = QVBoxLayout(widget)

        # Кнопки управления
        buttons_layout = QHBoxLayout()

        add_btn = QPushButton("Добавить")
        add_btn.clicked.connect(self.add_password)

        edit_btn = QPushButton("Редактировать")
        edit_btn.clicked.connect(self.edit_password)

        delete_btn = QPushButton("Удалить")
        delete_btn.clicked.connect(self.delete_password)

        refresh_btn = QPushButton("Обновить")
        refresh_btn.clicked.connect(self.load_passwords)

        buttons_layout.addWidget(add_btn)
        buttons_layout.addWidget(edit_btn)
        buttons_layout.addWidget(delete_btn)
        buttons_layout.addWidget(refresh_btn)

        # Паник-кнопка
        panic_layout = QHBoxLayout()
        panic_layout.addStretch()
        self.panic_button = QPushButton("ПАНИКА")
        self.panic_button.setStyleSheet("""
            QPushButton {
                background-color: #ff4444;
                color: white;
                font-weight: bold;
                font-size: 14px;
                border: 2px solid #cc0000;
                border-radius: 5px;
                padding: 10px 20px;
            }
            QPushButton:hover {
                background-color: #cc0000;
            }
            QPushButton:pressed {
                background-color: #990000;
            }
        """)
        self.panic_button.clicked.connect(self.activate_panic_mode)
        panic_layout.addWidget(self.panic_button)

        # Поиск
        search_layout = QHBoxLayout()
        self.search_input = QLineEdit()
        self.search_input.setPlaceholderText("Поиск по сервису...")
        self.search_input.textChanged.connect(self.search_passwords)
        search_layout.addWidget(QLabel("Поиск:"))
        search_layout.addWidget(self.search_input)

        # Таблица паролей
        self.passwords_table = QTableWidget()
        self.passwords_table.setColumnCount(4)
        self.passwords_table.setHorizontalHeaderLabels(["Сервис", "Логин", "Пароль", "Заметки"])
        self.passwords_table.horizontalHeader().setSectionResizeMode(QHeaderView.ResizeMode.Stretch)
        self.passwords_table.setContextMenuPolicy(Qt.ContextMenuPolicy.CustomContextMenu)
        self.passwords_table.customContextMenuRequested.connect(self.show_context_menu)

        layout.addLayout(buttons_layout)
        layout.addLayout(panic_layout)
        layout.addLayout(search_layout)
        layout.addWidget(self.passwords_table)

        self.load_passwords()
        return widget

    def show_context_menu(self, position):
        """Контекстное меню"""
        menu = QMenu(self)

        show_password_action = QAction("Показать пароль", self)
        show_password_action.triggered.connect(self.show_password)

        copy_password_action = QAction("Копировать пароль", self)
        copy_password_action.triggered.connect(self.copy_table_password)

        menu.addAction(show_password_action)
        menu.addAction(copy_password_action)
        menu.exec(QCursor.pos())

    def show_password(self):
        """Показать пароль"""
        current_row = self.passwords_table.currentRow()
        if current_row == -1:
            QMessageBox.warning(self, "Ошибка", "Выберите запись для просмотра")
            return

        service_item = self.passwords_table.item(current_row, 0)
        if service_item:
            service = service_item.text()
            encrypted_password = self.get_encrypted_password_from_db(service)

            if encrypted_password:
                decrypted_password = self.decrypt_data(encrypted_password)
                QMessageBox.information(
                    self,
                    f"Пароль для {service}",
                    f"Пароль: {decrypted_password}"
                )

    def copy_table_password(self):
        """Копировать пароль"""
        current_row = self.passwords_table.currentRow()
        if current_row == -1:
            QMessageBox.warning(self, "Ошибка", "Выберите запись")
            return

        service_item = self.passwords_table.item(current_row, 0)
        if service_item:
            service = service_item.text()
            encrypted_password = self.get_encrypted_password_from_db(service)

            if encrypted_password:
                decrypted_password = self.decrypt_data(encrypted_password)
                QApplication.clipboard().setText(decrypted_password)
                QMessageBox.information(self, "Успех", "Пароль скопирован в буфер обмена!")

    def get_encrypted_password_from_db(self, service):
        """Получение зашифрованного пароля из БД"""
        try:
            cursor = self.db_conn.cursor()
            cursor.execute("SELECT password_encrypted FROM passwords WHERE service = ?", (service,))
            result = cursor.fetchone()
            return result[0] if result else None
        except Exception as e:
            print(f"Ошибка получения пароля: {e}")
            return None

    def create_generator_tab(self):
        """Вкладка генератора"""
        widget = QWidget()
        layout = QVBoxLayout(widget)

        # Настройки
        settings_layout = QFormLayout()

        self.length_spin = QSpinBox()
        self.length_spin.setRange(8, 32)
        self.length_spin.setValue(16)

        self.uppercase_check = QCheckBox("A-Z (Верхний регистр)")
        self.uppercase_check.setChecked(True)

        self.lowercase_check = QCheckBox("a-z (Нижний регистр)")
        self.lowercase_check.setChecked(True)

        self.digits_check = QCheckBox("0-9 (Цифры)")
        self.digits_check.setChecked(True)

        self.symbols_check = QCheckBox("!@#$% (Символы)")
        self.symbols_check.setChecked(True)

        settings_layout.addRow("Длина пароля:", self.length_spin)
        settings_layout.addRow("", self.uppercase_check)
        settings_layout.addRow("", self.lowercase_check)
        settings_layout.addRow("", self.digits_check)
        settings_layout.addRow("", self.symbols_check)

        # Поле для пароля
        self.generated_password = QLineEdit()
        self.generated_password.setReadOnly(True)
        self.generated_password.setFont(QFont("Courier", 14))
        self.generated_password.setStyleSheet("padding: 10px; background: #f0f0f0;")

        # Кнопки
        buttons_layout = QHBoxLayout()
        generate_btn = QPushButton("Сгенерировать пароль")
        generate_btn.clicked.connect(self.generate_password)
        generate_btn.setStyleSheet("padding: 10px; font-size: 14px;")

        copy_btn = QPushButton("Копировать")
        copy_btn.clicked.connect(self.copy_password)
        copy_btn.setStyleSheet("padding: 10px; font-size: 14px;")

        buttons_layout.addWidget(generate_btn)
        buttons_layout.addWidget(copy_btn)

        layout.addLayout(settings_layout)
        layout.addWidget(QLabel("\n<b>Сгенерированный пароль:</b>"))
        layout.addWidget(self.generated_password)
        layout.addLayout(buttons_layout)
        layout.addStretch()

        return widget

    def create_settings_tab(self):
        """Вкладка настроек"""
        widget = QWidget()
        layout = QVBoxLayout(widget)

        # Информация
        info_label = QLabel(
            "<b>Мастер-пароль установлен</b><br>"
            "Используется для защиты доступа к приложению и шифрования данных."
        )
        info_label.setStyleSheet("color: green; padding: 10px; background: #e8f5e9; border-radius: 5px;")
        layout.addWidget(info_label)

        # Тест шифрования
        test_encryption_btn = QPushButton("Тест шифрования/дешифрования")
        test_encryption_btn.clicked.connect(self.test_encryption)
        layout.addWidget(test_encryption_btn)

        # Яндекс.Диск
        layout.addWidget(QLabel("\n<b>Яндекс.Диск - Облачное резервное копирование:</b>"))

        yandex_buttons = QHBoxLayout()

        setup_ydisk_btn = QPushButton("Настроить Яндекс.Диск")
        setup_ydisk_btn.clicked.connect(self.setup_yandex_disk)

        backup_btn = QPushButton("Создать резервную копию")
        backup_btn.clicked.connect(self.create_backup)

        restore_btn = QPushButton("Восстановить из бэкапа")
        restore_btn.clicked.connect(self.restore_from_backup)

        yandex_buttons.addWidget(setup_ydisk_btn)
        yandex_buttons.addWidget(backup_btn)
        yandex_buttons.addWidget(restore_btn)
        layout.addLayout(yandex_buttons)

        # Статус Яндекс.Диска
        ydisk_status = "Настроено и подключено" if (
                self.ydisk and self.ydisk.check_token_valid()) else "Не настроено"
        status_label = QLabel(f"Статус: {ydisk_status}")
        status_label.setStyleSheet("padding: 5px;")
        layout.addWidget(status_label)

        # Смена мастер-пароля
        layout.addWidget(QLabel("\n<b>Смена мастер-пароля:</b>"))
        change_pwd_layout = QFormLayout()

        self.new_master_input = QLineEdit()
        self.new_master_input.setEchoMode(QLineEdit.EchoMode.Password)
        self.new_master_input.setPlaceholderText("Новый пароль")

        self.new_master_confirm = QLineEdit()
        self.new_master_confirm.setEchoMode(QLineEdit.EchoMode.Password)
        self.new_master_confirm.setPlaceholderText("Подтверждение")

        change_pwd_layout.addRow("Новый мастер-пароль:", self.new_master_input)
        change_pwd_layout.addRow("Подтверждение:", self.new_master_confirm)
        layout.addLayout(change_pwd_layout)

        change_master_btn = QPushButton("Сменить мастер-пароль")
        change_master_btn.clicked.connect(self.change_master_password)
        layout.addWidget(change_master_btn)

        # Управление
        layout.addWidget(QLabel("\n<b>Управление приложением:</b>"))
        lock_btn = QPushButton("Заблокировать приложение")
        lock_btn.clicked.connect(self.lock_app)
        layout.addWidget(lock_btn)

        layout.addStretch()
        return widget

    def test_encryption(self):
        """Тестирование шифрования"""
        if not self.cipher_suite:
            QMessageBox.warning(self, "Ошибка", "Шифрование не инициализировано!")
            return

        test_text = "TestPassword123!@#"
        encrypted = self.encrypt_data(test_text)
        decrypted = self.decrypt_data(encrypted)
        success = test_text == decrypted

        result = f"<b>Тест шифрования:</b><br><br>"
        result += f"Оригинал: <code>{test_text}</code><br>"
        result += f"Зашифровано: <code>{encrypted[:50]}...</code><br>"
        result += f"Расшифровано: <code>{decrypted}</code><br><br>"
        result += f"<b>{'УСПЕШНО' if success else 'ОШИБКА'}</b>"

        QMessageBox.information(self, "Тест шифрования", result)

    def setup_yandex_disk(self):
        """Настройка Яндекс.Диска"""
        current_token = self.ydisk.token if self.ydisk else None
        dialog = YandexDiskSetupDialog(self, current_token)

        if dialog.exec() == QDialog.DialogCode.Accepted:
            self.save_ydisk_token(dialog.token)
            QMessageBox.information(self, "Успех", "Настройки Яндекс.Диска сохранены!")

            # Обновляем UI
            self.init_ui()

    def create_backup(self):
        """Создание резервной копии"""
        try:
            backup_name = f"passhub_backup_{datetime.now().strftime('%Y%m%d_%H%M%S')}.backup"

            if not os.path.exists('passhub.db'):
                QMessageBox.warning(self, "Ошибка", "База данных не найдена!")
                return

            # Создаем локальную копию
            shutil.copy2('passhub.db', backup_name)
            print(f"Локальная копия создана: {backup_name}")

            # Загружаем на Яндекс.Диск
            if self.ydisk and self.ydisk.check_token_valid():
                if self.ydisk.create_folder():
                    if self.ydisk.upload_file(backup_name):
                        QMessageBox.information(
                            self,
                            "Успех",
                            f"Резервная копия создана и загружена на Яндекс.Диск!\n\n"
                            f"Имя файла: {backup_name}"
                        )
                        print("Бэкап загружен на Яндекс.Диск")
                    else:
                        QMessageBox.warning(
                            self,
                            "Предупреждение",
                            "Локальная копия создана, но не удалось загрузить на Яндекс.Диск.\n"
                            "Проверьте подключение к интернету."
                        )
                else:
                    QMessageBox.warning(self, "Ошибка", "Не удалось создать папку на Яндекс.Диске")
            else:
                QMessageBox.information(
                    self,
                    "Успех",
                    f"Локальная резервная копия создана!\n\n"
                    f"Имя файла: {backup_name}\n\n"
                    "Для автоматической загрузки в облако настройте Яндекс.Диск в настройках."
                )

            # Удаляем временный файл через 5 секунд
            QTimer.singleShot(5000, lambda: self.cleanup_backup_file(backup_name))

        except Exception as e:
            print(f"Ошибка создания бэкапа: {e}")
            QMessageBox.critical(self, "Ошибка", f"Не удалось создать резервную копию:\n{e}")

    def cleanup_backup_file(self, backup_name):
        """Удаление временного файла бэкапа"""
        try:
            if os.path.exists(backup_name):
                os.remove(backup_name)
                print(f"Временный файл {backup_name} удален")
        except Exception as e:
            print(f"Ошибка удаления: {e}")

    def restore_from_backup(self):
        """Восстановление из бэкапа"""
        if not self.ydisk or not self.ydisk.check_token_valid():
            QMessageBox.warning(
                self,
                "Ошибка",
                "Не настроено подключение к Яндекс.Диску!\n\n"
                "Сначала настройте Яндекс.Диск в разделе настроек."
            )
            return

        dialog = BackupRestoreDialog(self, self.ydisk)
        if dialog.exec() == QDialog.DialogCode.Accepted and dialog.selected_backup:
            backup_name = dialog.selected_backup
            temp_file = f"temp_restore_{backup_name}"

            try:
                # Скачиваем бэкап
                if self.ydisk.download_file(backup_name, temp_file):
                    # Закрываем соединение с БД
                    if self.db_conn:
                        self.db_conn.close()
                        self.db_conn = None

                    # Даем время на закрытие соединения
                    QApplication.processEvents()

                    # Создаем резервную копию текущей БД
                    if os.path.exists('passhub.db'):
                        shutil.copy2('passhub.db',
                                     f'passhub_before_restore_{datetime.now().strftime("%Y%m%d_%H%M%S")}.db')

                    # Заменяем БД
                    shutil.copy2(temp_file, 'passhub.db')

                    # Переинициализируем
                    self.init_database()
                    self.load_passwords()

                    # Удаляем временный файл
                    if os.path.exists(temp_file):
                        os.remove(temp_file)

                    QMessageBox.information(
                        self,
                        "Успех",
                        "Данные успешно восстановлены из резервной копии!\n\n"
                        "Приложение будет перезапущено."
                    )

                    # Перезапускаем приложение
                    QTimer.singleShot(1000, self.restart_app)

                else:
                    QMessageBox.critical(self, "Ошибка", "Не удалось скачать резервную копию!")

            except Exception as e:
                print(f"Ошибка восстановления: {e}")
                QMessageBox.critical(self, "Ошибка", f"Ошибка при восстановлении:\n{e}")
                # Восстанавливаем соединение с БД в случае ошибки
                self.init_database()

    def restart_app(self):
        """Перезапуск приложения"""
        self.close()
        QApplication.quit()

    def load_passwords(self):
        """Загрузка паролей"""
        if not self.db_conn or not self.is_authenticated:
            return

        try:
            cursor = self.db_conn.cursor()
            cursor.execute("SELECT service, username, password_encrypted, notes_encrypted FROM passwords")
            passwords = cursor.fetchall()

            self.passwords_table.setRowCount(len(passwords))

            for row, (service, username, password_enc, notes_enc) in enumerate(passwords):
                password_display = "••••••••"
                notes_display = self.decrypt_data(notes_enc) if notes_enc else ""

                self.passwords_table.setItem(row, 0, QTableWidgetItem(service))
                self.passwords_table.setItem(row, 1, QTableWidgetItem(username))
                self.passwords_table.setItem(row, 2, QTableWidgetItem(password_display))
                self.passwords_table.setItem(row, 3, QTableWidgetItem(notes_display[:50]))

            print(f"Загружено {len(passwords)} записей")

        except Exception as e:
            print(f"Ошибка загрузки: {e}")

    def add_password(self):
        """Добавление пароля"""
        if not self.is_authenticated:
            return

        dialog = AddPasswordDialog(self)
        if dialog.exec() == QDialog.DialogCode.Accepted:
            data = dialog.get_data()

            if not data['service'] or not data['username'] or not data['password']:
                QMessageBox.warning(self, "Ошибка", "Заполните все обязательные поля!")
                return

            try:
                password_encrypted = self.encrypt_data(data['password'])
                notes_encrypted = self.encrypt_data(data['notes']) if data['notes'] else ""

                cursor = self.db_conn.cursor()
                cursor.execute('''
                    INSERT INTO passwords (service, username, password_encrypted, notes_encrypted)
                    VALUES (?, ?, ?, ?)
                ''', (data['service'], data['username'], password_encrypted, notes_encrypted))

                self.db_conn.commit()
                self.load_passwords()
                QMessageBox.information(self, "Успех", "Пароль добавлен и зашифрован!")

            except Exception as e:
                QMessageBox.critical(self, "Ошибка", f"Не удалось добавить пароль:\n{e}")

    def edit_password(self):
        """Редактирование пароля"""
        current_row = self.passwords_table.currentRow()
        if current_row == -1:
            QMessageBox.warning(self, "Ошибка", "Выберите пароль для редактирования!")
            return

        # Получаем данные из таблицы
        service = self.passwords_table.item(current_row, 0).text()
        username = self.passwords_table.item(current_row, 1).text()

        # Получаем зашифрованные данные из БД
        try:
            cursor = self.db_conn.cursor()
            cursor.execute(
                "SELECT password_encrypted, notes_encrypted FROM passwords WHERE service = ?",
                (service,)
            )
            result = cursor.fetchone()

            if not result:
                QMessageBox.warning(self, "Ошибка", "Запись не найдена в базе данных!")
                return

            password_encrypted, notes_encrypted = result

            # Расшифровываем данные
            password_decrypted = self.decrypt_data(password_encrypted)
            notes_decrypted = self.decrypt_data(notes_encrypted) if notes_encrypted else ""

            # Создаем данные для диалога
            current_data = {
                'service': service,
                'username': username,
                'password': password_decrypted,
                'notes': notes_decrypted
            }

            # Открываем диалог редактирования
            dialog = AddPasswordDialog(self, edit_mode=True, data=current_data)
            if dialog.exec() == QDialog.DialogCode.Accepted:
                new_data = dialog.get_data()

                if not new_data['username'] or not new_data['password']:
                    QMessageBox.warning(self, "Ошибка", "Логин и пароль обязательны для заполнения!")
                    return

                # Шифруем новые данные
                password_encrypted = self.encrypt_data(new_data['password'])
                notes_encrypted = self.encrypt_data(new_data['notes']) if new_data['notes'] else ""

                # Обновляем запись в БД
                cursor.execute('''
                    UPDATE passwords 
                    SET username = ?, password_encrypted = ?, notes_encrypted = ?
                    WHERE service = ?
                ''', (new_data['username'], password_encrypted, notes_encrypted, service))

                self.db_conn.commit()
                self.load_passwords()
                QMessageBox.information(self, "Успех", "Пароль успешно обновлен!")

        except Exception as e:
            print(f"Ошибка редактирования: {e}")
            QMessageBox.critical(self, "Ошибка", f"Не удалось отредактировать пароль:\n{e}")

    def delete_password(self):
        """Удаление пароля"""
        current_row = self.passwords_table.currentRow()
        if current_row == -1:
            QMessageBox.warning(self, "Ошибка", "Выберите пароль для удаления!")
            return

        service = self.passwords_table.item(current_row, 0).text()

        reply = QMessageBox.question(
            self,
            "Подтверждение",
            f"Удалить пароль для '{service}'?",
            QMessageBox.StandardButton.Yes | QMessageBox.StandardButton.No
        )

        if reply == QMessageBox.StandardButton.Yes:
            try:
                cursor = self.db_conn.cursor()
                cursor.execute("DELETE FROM passwords WHERE service = ?", (service,))
                self.db_conn.commit()
                self.load_passwords()
                QMessageBox.information(self, "Успех", "Пароль удален!")
            except Exception as e:
                QMessageBox.critical(self, "Ошибка", f"Не удалось удалить пароль:\n{e}")

    def search_passwords(self):
        """Поиск паролей"""
        search_text = self.search_input.text().lower()

        for row in range(self.passwords_table.rowCount()):
            service_item = self.passwords_table.item(row, 0)
            username_item = self.passwords_table.item(row, 1)

            if service_item:
                service_match = search_text in service_item.text().lower()
                username_match = username_item and search_text in username_item.text().lower()
                self.passwords_table.setRowHidden(row, not (service_match or username_match))

    def generate_password(self):
        """Генератор паролей"""
        length = self.length_spin.value()

        characters = ""
        if self.lowercase_check.isChecked():
            characters += string.ascii_lowercase
        if self.uppercase_check.isChecked():
            characters += string.ascii_uppercase
        if self.digits_check.isChecked():
            characters += string.digits
        if self.symbols_check.isChecked():
            characters += "!@#$%^&*()_+-=[]{}|;:,.<>?"

        if not characters:
            QMessageBox.warning(self, "Ошибка", "Выберите хотя бы один тип символов!")
            return

        password = ''.join(secrets.choice(characters) for _ in range(length))
        self.generated_password.setText(password)

    def copy_password(self):
        """Копирование пароля"""
        password = self.generated_password.text()
        if password:
            QApplication.clipboard().setText(password)
            QMessageBox.information(self, "Успех", "Пароль скопирован в буфер обмена!")
        else:
            QMessageBox.warning(self, "Ошибка", "Сначала сгенерируйте пароль!")

    def change_master_password(self):
        """Смена мастер-пароля"""
        new_password = self.new_master_input.text()
        confirm_password = self.new_master_confirm.text()

        if not new_password or not confirm_password:
            QMessageBox.warning(self, "Ошибка", "Заполните все поля!")
            return

        if new_password != confirm_password:
            QMessageBox.warning(self, "Ошибка", "Пароли не совпадают!")
            return

        if len(new_password) < 4:
            QMessageBox.warning(self, "Ошибка", "Пароль должен быть не менее 4 символов!")
            return

        try:
            self.save_master_password(new_password)
            self.current_master_password = new_password
            self.init_encryption()

            self.new_master_input.clear()
            self.new_master_confirm.clear()
            QMessageBox.information(self, "Успех", "Мастер-пароль успешно изменен!")
        except Exception as e:
            QMessageBox.critical(self, "Ошибка", f"Ошибка при смене пароля:\n{e}")

    def lock_app(self):
        """Блокировка приложения"""
        self.is_authenticated = False
        self.hide()
        QMessageBox.information(None, "Блокировка", "Приложение заблокировано.\nТребуется повторный вход.")
        self.authenticate_user()
        if self.is_authenticated:
            self.show()
        else:
            QApplication.quit()

    def activate_panic_mode(self):
        """Активация паники"""
        dialog = PanicButtonDialog(self)
        if dialog.exec() == QDialog.DialogCode.Accepted:
            reply = QMessageBox.critical(
                self,
                "ПОДТВЕРЖДЕНИЕ ПАНИКИ",
                "<b>ВЫ АКТИВИРОВАЛИ РЕЖИМ ПАНИКИ!</b><br><br>"
                "Все данные будут <b>безвозвратно удалены</b> через 10 секунд.<br>"
                "Отмена возможна только в течение этого времени.<br><br>"
                "<b>Продолжить?</b>",
                QMessageBox.StandardButton.Yes | QMessageBox.StandardButton.No
            )

            if reply == QMessageBox.StandardButton.Yes:
                self.start_panic_sequence()

    def start_panic_sequence(self):
        """Запуск последовательности паники"""
        self.panic_activated = True
        self.panic_button.setEnabled(False)
        self.countdown = 10
        self.panic_timer.start(1000)

    def emergency_cleanup(self):
        """Обратный отсчет паники"""
        self.countdown -= 1

        if self.countdown > 0:
            self.panic_button.setText(f"УДАЛЕНИЕ ЧЕРЕЗ {self.countdown}с")

            if self.countdown == 5:
                reply = QMessageBox.question(
                    self,
                    "ОТМЕНА ПАНИКИ",
                    f"Осталось {self.countdown} секунд до удаления данных!\n\nОтменить панику?",
                    QMessageBox.StandardButton.Yes | QMessageBox.StandardButton.No
                )

                if reply == QMessageBox.StandardButton.Yes:
                    self.cancel_panic()
                    return
        else:
            self.execute_data_destruction()

    def cancel_panic(self):
        """Отмена паники"""
        self.panic_timer.stop()
        self.panic_activated = False
        self.panic_button.setText("ПАНИКА")
        self.panic_button.setEnabled(True)
        self.panic_button.setStyleSheet("""
            QPushButton {
                background-color: #ff4444;
                color: white;
                font-weight: bold;
                font-size: 14px;
                border: 2px solid #cc0000;
                border-radius: 5px;
                padding: 10px;
            }
            QPushButton:hover {
                background-color: #cc0000;
            }
        """)
        QMessageBox.information(self, "Паника отменена", "Режим паники деактивирован.")

    def execute_data_destruction(self):
        """Выполнение удаления данных"""
        try:
            self.panic_timer.stop()

            # Закрываем соединение с БД ПЕРЕД удалением
            if hasattr(self, 'db_conn') and self.db_conn:
                print("Закрываем соединение с базой данных...")
                self.db_conn.close()
                self.db_conn = None

            # Даем время на закрытие соединения
            QApplication.processEvents()

            # Пытаемся удалить базу данных
            db_file = 'passhub.db'
            if os.path.exists(db_file):
                print("Пытаемся удалить базу данных...")

                # Пробуем несколько раз на случай блокировки файла
                for attempt in range(5):
                    try:
                        os.remove(db_file)
                        print("База данных успешно удалена")
                        break
                    except PermissionError as e:
                        print(f"Попытка {attempt + 1}: Файл заблокирован, ждем...")
                        time.sleep(0.5)  # Ждем 500ms перед повторной попыткой
                        if attempt == 4:  # Последняя попытка
                            print("Не удалось удалить базу данных - файл заблокирован")
                            # Показываем пользователю информацию
                            QMessageBox.warning(self, "Предупреждение",
                                                "Не удалось полностью удалить базу данных.\n"
                                                "Файл может быть заблокирован системой.\n"
                                                "Рекомендуется удалить файл вручную: passhub.db")

            # Удаляем резервные копии
            backup_deleted = 0
            for file in os.listdir('.'):
                if file.startswith('passhub_backup_') and file.endswith('.backup'):
                    try:
                        os.remove(file)
                        backup_deleted += 1
                        print(f"Резервная копия {file} удалена")
                    except Exception as e:
                        print(f"Не удалось удалить {file}: {e}")

            # Очищаем таблицу паролей в интерфейсе
            if hasattr(self, 'passwords_table'):
                self.passwords_table.setRowCount(0)

            self.is_authenticated = False

            # Сообщение об успехе
            message = "Все данные были успешно удалены.\nПриложение будет закрыто."
            if backup_deleted > 0:
                message += f"\nУдалено резервных копий: {backup_deleted}"

            QMessageBox.information(self, "Данные уничтожены", message)

            # Закрываем приложение
            QApplication.quit()

        except Exception as e:
            print(f"Критическая ошибка при удалении данных: {e}")
            QMessageBox.critical(self, "Ошибка",
                                 f"Не удалось полностью очистить данные: {str(e)}\n"
                                 "Приложение будет закрыто.")
            QApplication.quit()

    def closeEvent(self, event):
        """Обработчик закрытия окна"""
        # Закрываем соединение с БД при обычном закрытии
        if hasattr(self, 'db_conn') and self.db_conn:
            try:
                print("Закрываем соединение с БД...")
                self.db_conn.close()
            except Exception as e:
                print(f"Ошибка при закрытии соединения: {e}")

        if self.panic_activated:
            reply = QMessageBox.question(self, "Паника активна",
                                         "Режим паники активен! При закрытии приложения данные "
                                         "будут удалены без возможности восстановления.\n\n"
                                         "Все равно закрыть?",
                                         QMessageBox.StandardButton.Yes | QMessageBox.StandardButton.No)

            if reply == QMessageBox.StandardButton.No:
                event.ignore()
                return

        event.accept()


def main():
    app = QApplication(sys.argv)

    window = PasswordManager()

    if window.is_authenticated:
        window.show()
        sys.exit(app.exec())
    else:
        sys.exit(1)


if __name__ == '__main__':
    main()
