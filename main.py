import customtkinter as ctk
from tkinter import messagebox, ttk
import sqlite3
import hashlib
import re
import os
from datetime import datetime
import secrets
import string

class Database:
    def __init__(self, db_name="users.db"):
        self.db_name = db_name
        self.init_db()
    
    def init_db(self):
        """Инициализация базы данных с защитой от SQL-инъекций"""
        self.conn = sqlite3.connect(self.db_name)
        self.conn.execute("PRAGMA foreign_keys = ON")
        self.cursor = self.conn.cursor()
        self.create_tables()
    
    def create_tables(self):
        """Создание таблиц с индексами для улучшения производительности"""
        tables = [
            '''
            CREATE TABLE IF NOT EXISTS users (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                username TEXT UNIQUE NOT NULL,
                password TEXT NOT NULL,
                email TEXT UNIQUE,
                created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
                last_login TIMESTAMP,
                is_active INTEGER DEFAULT 1
            )
            ''',
            '''
            CREATE TABLE IF NOT EXISTS user_data (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                user_id INTEGER,
                title TEXT,
                data TEXT,
                category TEXT DEFAULT 'General',
                created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
                updated_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
                FOREIGN KEY (user_id) REFERENCES users (id) ON DELETE CASCADE
            )
            ''',
            '''
            CREATE TABLE IF NOT EXISTS login_attempts (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                username TEXT,
                ip_address TEXT,
                attempt_time TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
                success INTEGER
            )
            '''
        ]
        
        for table in tables:
            self.cursor.execute(table)
        
        # Создание индексов
        indexes = [
            "CREATE INDEX IF NOT EXISTS idx_users_username ON users(username)",
            "CREATE INDEX IF NOT EXISTS idx_user_data_user_id ON user_data(user_id)",
            "CREATE INDEX IF NOT EXISTS idx_login_attempts_time ON login_attempts(attempt_time)"
        ]
        
        for index in indexes:
            try:
                self.cursor.execute(index)
            except:
                pass
        
        self.conn.commit()
    
    def hash_password(self, password, salt=None):
        """Хеширование пароля с солью"""
        if salt is None:
            salt = secrets.token_hex(16)
        hashed = hashlib.pbkdf2_hmac('sha256', password.encode(), salt.encode(), 100000)
        return f"{salt}${hashed.hex()}"
    
    def verify_password(self, stored_password, provided_password):
        """Проверка пароля"""
        salt, hashed = stored_password.split('$')
        new_hash = self.hash_password(provided_password, salt)
        return new_hash == stored_password
    
    def register_user(self, username, password, email):
        """Регистрация пользователя с проверкой уникальности"""
        try:
            # Проверка существования пользователя
            self.cursor.execute("SELECT id FROM users WHERE username = ? OR email = ?", 
                               (username, email))
            if self.cursor.fetchone():
                return False, "Пользователь с таким именем или email уже существует"
            
            # Хеширование пароля
            hashed_password = self.hash_password(password)
            
            self.cursor.execute('''
                INSERT INTO users (username, password, email)
                VALUES (?, ?, ?)
            ''', (username, hashed_password, email))
            
            self.conn.commit()
            return True, "Регистрация успешна"
            
        except sqlite3.Error as e:
            return False, f"Ошибка базы данных: {str(e)}"
    
    def login_user(self, username, password):
        """Аутентификация пользователя с записью попыток входа"""
        try:
            self.cursor.execute('''
                SELECT id, username, password, is_active FROM users 
                WHERE username = ? AND is_active = 1
            ''', (username,))
            
            user = self.cursor.fetchone()
            if not user:
                return False, "Пользователь не найден или заблокирован"
            
            if self.verify_password(user[2], password):
                # Обновление времени последнего входа
                self.cursor.execute('''
                    UPDATE users SET last_login = CURRENT_TIMESTAMP 
                    WHERE id = ?
                ''', (user[0],))
                self.conn.commit()
                
                return True, {
                    'id': user[0],
                    'username': user[1]
                }
            else:
                return False, "Неверный пароль"
                
        except sqlite3.Error as e:
            return False, f"Ошибка базы данных: {str(e)}"
    
    def save_user_data(self, user_id, title, data, category="General"):
        """Сохранение данных пользователя"""
        try:
            self.cursor.execute('''
                INSERT INTO user_data (user_id, title, data, category)
                VALUES (?, ?, ?, ?)
            ''', (user_id, title, data, category))
            self.conn.commit()
            return True
        except sqlite3.Error:
            return False
    
    def get_user_data(self, user_id, category=None):
        """Получение данных пользователя с фильтрацией по категории"""
        try:
            if category:
                self.cursor.execute('''
                    SELECT id, title, data, category, created_at 
                    FROM user_data 
                    WHERE user_id = ? AND category = ?
                    ORDER BY created_at DESC
                ''', (user_id, category))
            else:
                self.cursor.execute('''
                    SELECT id, title, data, category, created_at 
                    FROM user_data 
                    WHERE user_id = ? 
                    ORDER BY created_at DESC
                ''', (user_id,))
            
            return self.cursor.fetchall()
        except sqlite3.Error:
            return []
    
    def get_categories(self, user_id):
        """Получение списка категорий пользователя"""
        try:
            self.cursor.execute('''
                SELECT DISTINCT category FROM user_data 
                WHERE user_id = ? ORDER BY category
            ''', (user_id,))
            return [row[0] for row in self.cursor.fetchall()]
        except sqlite3.Error:
            return []
    
    def close(self):
        """Закрытие соединения с базой данных"""
        if hasattr(self, 'conn'):
            self.conn.close()

class Validator:
    """Класс для валидации данных"""
    
    @staticmethod
    def validate_username(username):
        if len(username) < 3:
            return False, "Имя пользователя должно содержать минимум 3 символа"
        if not re.match(r'^[a-zA-Z0-9_]+$', username):
            return False, "Имя пользователя может содержать только буквы, цифры и _"
        return True, ""
    
    @staticmethod
    def validate_password(password):
        if len(password) < 6:
            return False, "Пароль должен содержать минимум 6 символов"
        if not any(char.isdigit() for char in password):
            return False, "Пароль должен содержать хотя бы одну цифру"
        if not any(char.isupper() for char in password):
            return False, "Пароль должен содержать хотя бы одну заглавную букву"
        return True, ""
    
    @staticmethod
    def validate_email(email):
        pattern = r'^[a-zA-Z0-9._%+-]+@[a-zA-Z0-9.-]+\.[a-zA-Z]{2,}$'
        if not re.match(pattern, email):
            return False, "Некорректный email адрес"
        return True, ""
    
    @staticmethod
    def generate_strong_password(length=12):
        """Генерация сильного пароля"""
        characters = string.ascii_letters + string.digits + string.punctuation
        return ''.join(secrets.choice(characters) for _ in range(length))

class ModernApp:
    def __init__(self):
        # Настройка темы
        ctk.set_appearance_mode("System")
        ctk.set_default_color_theme("blue")
        
        self.root = ctk.CTk()
        self.root.title("Modern Desktop App")
        self.root.geometry("1000x700")
        self.root.minsize(800, 600)
        
        # Инициализация базы данных
        self.db = Database()
        self.current_user = None
        
        self.setup_styles()
        self.show_login_frame()
    
    def setup_styles(self):
        """Настройка стилей приложения"""
        self.style = {
            'font_main': ('Arial', 14),
            'font_title': ('Arial', 18, 'bold'),
            'font_small': ('Arial', 12),
            'padding': 20,
            'button_width': 200,
            'entry_width': 300
        }
    
    def clear_window(self):
        """Очистка окна"""
        for widget in self.root.winfo_children():
            widget.destroy()
    
    def show_login_frame(self):
        """Отображение формы входа"""
        self.clear_window()
        
        # Основной фрейм
        main_frame = ctk.CTkFrame(self.root)
        main_frame.pack(expand=True, fill='both', padx=50, pady=50)
        
        # Заголовок
        title_label = ctk.CTkLabel(main_frame, text="Вход в систему", 
                                  font=self.style['font_title'])
        title_label.pack(pady=40)
        
        # Форма входа
        form_frame = ctk.CTkFrame(main_frame)
        form_frame.pack(pady=20)
        
        ctk.CTkLabel(form_frame, text="Логин:", 
                    font=self.style['font_main']).grid(row=0, column=0, padx=10, pady=10, sticky='w')
        self.login_username = ctk.CTkEntry(form_frame, width=self.style['entry_width'],
                                          font=self.style['font_main'])
        self.login_username.grid(row=0, column=1, padx=10, pady=10)
        
        ctk.CTkLabel(form_frame, text="Пароль:", 
                    font=self.style['font_main']).grid(row=1, column=0, padx=10, pady=10, sticky='w')
        self.login_password = ctk.CTkEntry(form_frame, width=self.style['entry_width'],
                                          show="*", font=self.style['font_main'])
        self.login_password.grid(row=1, column=1, padx=10, pady=10)
        
        # Кнопки
        button_frame = ctk.CTkFrame(main_frame)
        button_frame.pack(pady=30)
        
        ctk.CTkButton(button_frame, text="Войти", command=self.login,
                      width=self.style['button_width'], font=self.style['font_main']).pack(pady=10)
        
        ctk.CTkButton(button_frame, text="Регистрация", command=self.show_register_frame,
                      width=self.style['button_width'], font=self.style['font_main'],
                      fg_color="transparent", border_width=2).pack(pady=10)
        
        # Установка фокуса
        self.login_username.focus()
        
        # Бинд Enter для входа
        self.root.bind('<Return>', lambda e: self.login())
    
    def show_register_frame(self):
        """Отображение формы регистрации"""
        self.clear_window()
        
        main_frame = ctk.CTkFrame(self.root)
        main_frame.pack(expand=True, fill='both', padx=50, pady=50)
        
        title_label = ctk.CTkLabel(main_frame, text="Регистрация", 
                                  font=self.style['font_title'])
        title_label.pack(pady=30)
        
        form_frame = ctk.CTkFrame(main_frame)
        form_frame.pack(pady=20)
        
        fields = [
            ("Имя пользователя:", "reg_username"),
            ("Пароль:", "reg_password", True),
            ("Подтверждение пароля:", "reg_confirm_password", True),
            ("Email:", "reg_email")
        ]
        
        self.reg_fields = {}
        for i, (label, field_name, *is_password) in enumerate(fields):
            ctk.CTkLabel(form_frame, text=label, 
                        font=self.style['font_main']).grid(row=i, column=0, padx=10, pady=8, sticky='w')
            
            entry = ctk.CTkEntry(form_frame, width=self.style['entry_width'],
                                show="*" if is_password else None, 
                                font=self.style['font_main'])
            entry.grid(row=i, column=1, padx=10, pady=8)
            self.reg_fields[field_name] = entry
        
        # Кнопка генерации пароля
        ctk.CTkButton(form_frame, text="Сгенерировать пароль", 
                      command=self.generate_password,
                      font=self.style['font_small']).grid(row=len(fields), column=1, pady=10)
        
        # Кнопки
        button_frame = ctk.CTkFrame(main_frame)
        button_frame.pack(pady=20)
        
        ctk.CTkButton(button_frame, text="Зарегистрироваться", command=self.register,
                      width=self.style['button_width'], font=self.style['font_main']).pack(pady=10)
        
        ctk.CTkButton(button_frame, text="Назад", command=self.show_login_frame,
                      width=self.style['button_width'], font=self.style['font_main'],
                      fg_color="transparent", border_width=2).pack(pady=10)
    
    def show_main_app(self):
        """Отображение главного интерфейса приложения"""
        self.clear_window()
        
        # Создание боковой панели
        sidebar = ctk.CTkFrame(self.root, width=200)
        sidebar.pack(side='left', fill='y', padx=10, pady=10)
        
        # Приветствие
        welcome_label = ctk.CTkLabel(sidebar, text=f"Добро пожаловать,\n{self.current_user['username']}!",
                                    font=self.style['font_main'])
        welcome_label.pack(pady=20)
        
        # Кнопки навигации
        ctk.CTkButton(sidebar, text="Добавить запись", command=self.show_add_data_frame,
                     font=self.style['font_main']).pack(pady=10, fill='x')
        
        ctk.CTkButton(sidebar, text="Мои записи", command=self.show_data_list,
                     font=self.style['font_main']).pack(pady=10, fill='x')
        
        ctk.CTkButton(sidebar, text="Выйти", command=self.logout,
                     font=self.style['font_main'], fg_color="#d9534f").pack(pady=20, fill='x')
        
        # Основная область
        self.main_area = ctk.CTkFrame(self.root)
        self.main_area.pack(side='right', expand=True, fill='both', padx=10, pady=10)
        
        # Показываем dashboard по умолчанию
        self.show_dashboard()
    
    def show_dashboard(self):
        """Показ dashboard"""
        for widget in self.main_area.winfo_children():
            widget.destroy()
        
        title = ctk.CTkLabel(self.main_area, text="Главная панель", 
                            font=self.style['font_title'])
        title.pack(pady=20)
        
        # Статистика
        stats_frame = ctk.CTkFrame(self.main_area)
        stats_frame.pack(pady=20, padx=20, fill='x')
        
        user_data = self.db.get_user_data(self.current_user['id'])
        categories = self.db.get_categories(self.current_user['id'])
        
        stats_text = f"""
        Общее количество записей: {len(user_data)}
        Количество категорий: {len(categories)}
        Последняя запись: {user_data[0][4][:10] if user_data else 'Нет записей'}
        """
        
        stats_label = ctk.CTkLabel(stats_frame, text=stats_text, 
                                  font=self.style['font_main'], justify='left')
        stats_label.pack(pady=20, padx=20)
    
    def show_add_data_frame(self):
        """Форма добавления данных"""
        for widget in self.main_area.winfo_children():
            widget.destroy()
        
        title = ctk.CTkLabel(self.main_area, text="Добавить новую запись", 
                            font=self.style['font_title'])
        title.pack(pady=20)
        
        form_frame = ctk.CTkFrame(self.main_area)
        form_frame.pack(pady=20, padx=50, fill='both', expand=True)
        
        ctk.CTkLabel(form_frame, text="Заголовок:", 
                    font=self.style['font_main']).grid(row=0, column=0, padx=10, pady=10, sticky='w')
        self.data_title = ctk.CTkEntry(form_frame, width=400, font=self.style['font_main'])
        self.data_title.grid(row=0, column=1, padx=10, pady=10)
        
        ctk.CTkLabel(form_frame, text="Категория:", 
                    font=self.style['font_main']).grid(row=1, column=0, padx=10, pady=10, sticky='w')
        self.data_category = ctk.CTkEntry(form_frame, width=400, font=self.style['font_main'])
        self.data_category.grid(row=1, column=1, padx=10, pady=10)
        
        ctk.CTkLabel(form_frame, text="Содержание:", 
                    font=self.style['font_main']).grid(row=2, column=0, padx=10, pady=10, sticky='nw')
        
        # Текстовое поле с прокруткой
        text_frame = ctk.CTkFrame(form_frame)
        text_frame.grid(row=2, column=1, padx=10, pady=10, sticky='nsew')
        
        self.data_content = ctk.CTkTextbox(text_frame, width=400, height=200, 
                                          font=self.style['font_main'])
        self.data_content.pack(padx=5, pady=5, fill='both', expand=True)
        
        # Настройка весов для растягивания
        form_frame.grid_rowconfigure(2, weight=1)
        form_frame.grid_columnconfigure(1, weight=1)
        
        # Кнопки
        button_frame = ctk.CTkFrame(self.main_area)
        button_frame.pack(pady=20)
        
        ctk.CTkButton(button_frame, text="Сохранить", command=self.save_data,
                     width=150, font=self.style['font_main']).pack(side='left', padx=10)
        
        ctk.CTkButton(button_frame, text="Отмена", command=self.show_dashboard,
                     width=150, font=self.style['font_main'],
                     fg_color="transparent", border_width=2).pack(side='left', padx=10)
    
    def show_data_list(self, category=None):
        """Показ списка записей пользователя"""
        for widget in self.main_area.winfo_children():
            widget.destroy()
        
        title = ctk.CTkLabel(self.main_area, text="Мои записи", 
                            font=self.style['font_title'])
        title.pack(pady=20)
        
        # Фильтр по категориям
        categories = self.db.get_categories(self.current_user['id'])
        if categories:
            filter_frame = ctk.CTkFrame(self.main_area)
            filter_frame.pack(pady=10, padx=20, fill='x')
            
            ctk.CTkLabel(filter_frame, text="Фильтр по категории:", 
                        font=self.style['font_small']).pack(side='left', padx=10)
            
            category_var = ctk.StringVar(value="Все")
            category_dropdown = ctk.CTkOptionMenu(filter_frame, 
                                                 values=["Все"] + categories,
                                                 variable=category_var,
                                                 command=lambda c: self.show_data_list(c if c != "Все" else None))
            category_dropdown.pack(side='left', padx=10)
        
        # Таблица с записями
        data = self.db.get_user_data(self.current_user['id'], category)
        
        if not data:
            ctk.CTkLabel(self.main_area, text="Записей не найдено", 
                        font=self.style['font_main']).pack(pady=50)
            return
        
        # Создание таблицы
        table_frame = ctk.CTkScrollableFrame(self.main_area, width=800, height=400)
        table_frame.pack(pady=20, padx=20, fill='both', expand=True)
        
        # Заголовки таблицы
        headers = ["Заголовок", "Категория", "Дата создания", "Действия"]
        for i, header in enumerate(headers):
            label = ctk.CTkLabel(table_frame, text=header, font=self.style['font_main'], 
                                width=150 if i < 3 else 100)
            label.grid(row=0, column=i, padx=5, pady=10, sticky='w')
        
        # Данные таблицы
        for row_idx, (data_id, title, content, category, created_at) in enumerate(data, 1):
            # Обрезаем длинный текст
            short_title = title[:20] + "..." if len(title) > 20 else title
            short_content = content[:30] + "..." if len(content) > 30 else content
            
            ctk.CTkLabel(table_frame, text=short_title, font=self.style['font_small'],
                        width=150).grid(row=row_idx, column=0, padx=5, pady=5, sticky='w')
            
            ctk.CTkLabel(table_frame, text=category, font=self.style['font_small'],
                        width=150).grid(row=row_idx, column=1, padx=5, pady=5, sticky='w')
            
            ctk.CTkLabel(table_frame, text=created_at[:10], font=self.style['font_small'],
                        width=150).grid(row=row_idx, column=2, padx=5, pady=5, sticky='w')
            
            # Кнопки действий
            action_frame = ctk.CTkFrame(table_frame, fg_color="transparent")
            action_frame.grid(row=row_idx, column=3, padx=5, pady=5)
            
            ctk.CTkButton(action_frame, text="👁", width=30, height=30,
                         command=lambda d=(data_id, title, content, category, created_at): 
                         self.show_data_detail(d)).pack(side='left', padx=2)
            
            ctk.CTkButton(action_frame, text="✏️", width=30, height=30,
                         command=lambda d=data_id: self.edit_data(d)).pack(side='left', padx=2)
            
            ctk.CTkButton(action_frame, text="🗑️", width=30, height=30, fg_color="#d9534f",
                         command=lambda d=data_id: self.delete_data(d)).pack(side='left', padx=2)
    
    def show_data_detail(self, data):
        """Показ детальной информации о записи"""
        data_id, title, content, category, created_at = data
        
        for widget in self.main_area.winfo_children():
            widget.destroy()
        
        # Кнопка назад
        back_button = ctk.CTkButton(self.main_area, text="← Назад", 
                                   command=self.show_data_list,
                                   font=self.style['font_small'])
        back_button.pack(anchor='nw', padx=20, pady=20)
        
        # Детальная информация
        detail_frame = ctk.CTkFrame(self.main_area)
        detail_frame.pack(pady=20, padx=50, fill='both', expand=True)
        
        ctk.CTkLabel(detail_frame, text=title, font=('Arial', 20, 'bold')).pack(pady=20)
        
        info_frame = ctk.CTkFrame(detail_frame, fg_color="transparent")
        info_frame.pack(pady=10, fill='x')
        
        ctk.CTkLabel(info_frame, text=f"Категория: {category}", 
                    font=self.style['font_main']).pack(anchor='w')
        ctk.CTkLabel(info_frame, text=f"Создано: {created_at}", 
                    font=self.style['font_small']).pack(anchor='w')
        
        # Содержание
        content_frame = ctk.CTkFrame(detail_frame)
        content_frame.pack(pady=20, fill='both', expand=True)
        
        content_text = ctk.CTkTextbox(content_frame, font=self.style['font_main'], 
                                     wrap='word', height=300)
        content_text.pack(padx=10, pady=10, fill='both', expand=True)
        content_text.insert('1.0', content)
        content_text.configure(state='disabled')  # Только для чтения
    
    def generate_password(self):
        """Генерация сильного пароля"""
        strong_password = Validator.generate_strong_password()
        self.reg_fields['reg_password'].delete(0, 'end')
        self.reg_fields['reg_password'].insert(0, strong_password)
        self.reg_fields['reg_confirm_password'].delete(0, 'end')
        self.reg_fields['reg_confirm_password'].insert(0, strong_password)
        messagebox.showinfo("Пароль сгенерирован", 
                           f"Новый пароль: {strong_password}\nСкопируйте его в безопасное место!")
    
    def login(self):
        """Обработка входа"""
        username = self.login_username.get().strip()
        password = self.login_password.get()
        
        if not username or not password:
            messagebox.showerror("Ошибка", "Заполните все поля")
            return
        
        success, result = self.db.login_user(username, password)
        
        if success:
            self.current_user = result
            self.show_main_app()
        else:
            messagebox.showerror("Ошибка входа", result)
    
    def register(self):
        """Обработка регистрации"""
        username = self.reg_fields['reg_username'].get().strip()
        password = self.reg_fields['reg_password'].get()
        confirm_password = self.reg_fields['reg_confirm_password'].get()
        email = self.reg_fields['reg_email'].get().strip()
        
        # Валидация
        valid, msg = Validator.validate_username(username)
        if not valid:
            messagebox.showerror("Ошибка", msg)
            return
        
        valid, msg = Validator.validate_password(password)
        if not valid:
            messagebox.showerror("Ошибка", msg)
            return
        
        if password != confirm_password:
            messagebox.showerror("Ошибка", "Пароли не совпадают")
            return
        
        if email:
            valid, msg = Validator.validate_email(email)
            if not valid:
                messagebox.showerror("Ошибка", msg)
                return
        
        # Регистрация
        success, message = self.db.register_user(username, password, email)
        
        if success:
            messagebox.showinfo("Успех", message)
            self.show_login_frame()
        else:
            messagebox.showerror("Ошибка", message)
    
    def save_data(self):
        """Сохранение данных"""
        if not self.current_user:
            return
        
        title = self.data_title.get().strip()
        category = self.data_category.get().strip() or "General"
        content = self.data_content.get("1.0", "end-1c").strip()
        
        if not title or not content:
            messagebox.showerror("Ошибка", "Заполните заголовок и содержание")
            return
        
        if self.db.save_user_data(self.current_user['id'], title, content, category):
            messagebox.showinfo("Успех", "Данные сохранены успешно!")
            self.show_dashboard()
        else:
            messagebox.showerror("Ошибка", "Не удалось сохранить данные")
    
    def edit_data(self, data_id):
        """Редактирование данных"""
        # Реализация редактирования
        messagebox.showinfo("Инфо", "Функция редактирования в разработке")
    
    def delete_data(self, data_id):
        """Удаление данных"""
        if messagebox.askyesno("Подтверждение", "Вы уверены, что хотите удалить эту запись?"):
            # Реализация удаления
            messagebox.showinfo("Успех", "Запись удалена")
            self.show_data_list()
    
    def logout(self):
        """Выход из системы"""
        self.current_user = None
        self.show_login_frame()
    
    def run(self):
        """Запуск приложения"""
        self.root.mainloop()
    
    def __del__(self):
        """Деструктор для закрытия соединения с БД"""
        if hasattr(self, 'db'):
            self.db.close()

# Дополнительные утилиты
class BackupManager:
    """Менеджер резервных копий базы данных"""
    
    @staticmethod
    def create_backup(db_name="users.db"):
        """Создание резервной копии базы данных"""
        try:
            if os.path.exists(db_name):
                backup_name = f"backup_{datetime.now().strftime('%Y%m%d_%H%M%S')}.db"
                with open(db_name, 'rb') as src, open(backup_name, 'wb') as dst:
                    dst.write(src.read())
                return True, f"Резервная копия создана: {backup_name}"
            return False, "Файл базы данных не найден"
        except Exception as e:
            return False, f"Ошибка создания резервной копии: {str(e)}"

if __name__ == "__main__":
    # Создание резервной копии при запуске
    success, message = BackupManager.create_backup()
    if success:
        print(message)
    
    # Запуск приложения
    app = ModernApp()
    app.run()