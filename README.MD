# Безопасный ресторанный рекомендатель — шаблон ответственности в облаке

Этот проект реализует шаблон безопасности для систем ресторанных рекомендаций в облачных средах, уделяя особое внимание угрозе неопределенной ответственности между поставщиком облачных услуг и владельцем сервиса.

## 🔧 Функции
- Отслеживает и отображает текущие назначения ответственности
- Обнаруживает неназначенные обязанности по безопасности
- Регистрирует критические события безопасности
- Веб-интерфейс для видимости и контроля

## 🐳 Быстрый старт (Docker)

```bash
git clone https://github.com/Hanemiyaaaa/secure_pattern
cd secure-pattern

docker-compose up --build
```

Перейдите по ссылке [http://localhost:8000](http://localhost:8000) для взаимодействия с API.
Перейдите по ссылке [http://localhost:8000/frontend/index.html](http://localhost:8000/frontend/index.html) для интерфейса.

## 📦 Конечные точки API
- `GET /health` — состояние системы
- `GET /policy` — получить текущую политику ответственности
- `GET /responsibility_gap` — список неназначенных областей
- `POST /log_event` — записать событие безопасности (JSON: { "event": "..." })

## 📂 Файлы и структура
```
secure-pattern/
├── backend/
│ ├── main.py # Основной backend FastAPI
│ ├── auth.py # Аутентификация и авторизация
│ ├── database.py # Подключение и настройка БД
│ ├── models.py # ORM-модели для SQLAlchemy
│ ├── init_db.py # Инициализация базы данных
│ ├── services.py # Вспомогательные сервисы (логирование, загрузка политики)
│ ├── security_policy.json # Политика безопасности
│ ├── utils.py # Утилиты (валидация политики, вызов облака)
├── frontend/
│ └── index.html # Веб-интерфейс
├── Dockerfile # Dockerfile для backend
├── docker-compose.yml # Конфигурация Docker Compose
```

## 🔐 Пример политики
```json
{
"data_storage": "unassigned",
"data_encryption": "cloud_provider",
"access_control": "restaurant_owner",
"incident_response": "unassigned"
}
```

## 📜 Лицензия
MIT — бесплатное использование, адаптация и распространение.