import json
import hashlib
import requests
import time

POLICY_PATH = "security_policy.json"

def load_and_validate_policy():
    with open(POLICY_PATH, "r", encoding="utf-8") as f:
        policy_data = json.load(f)

    content = json.dumps(policy_data, sort_keys=True).encode("utf-8")
    checksum = hashlib.sha256(content).hexdigest()

    return policy_data, checksum


def call_cloud_service_with_fallback():
    """
    Пытается вызвать внешний облачный сервис.
    Если сервис недоступен, переходит в резервный режим (fallback).
    """
    cloud_url = "https://example-cloud-service/api/status"
    fallback_message = "Cloud service unreachable, fallback mode activated."

    try:
        response = requests.get(cloud_url, timeout=3)
        if response.status_code == 200:
            print("Cloud service is reachable.")
            # Можно добавить логику работы с облаком здесь
        else:
            print(f"Cloud service returned status {response.status_code}, activating fallback.")
            activate_fallback()
    except requests.RequestException:
        print(fallback_message)
        activate_fallback()

def activate_fallback():
    """
    Логика работы в резервном режиме при сбоях связи с облаком.
    """
    print("Running in fallback mode: limited functionality enabled.")
    # Здесь можно ограничить функциональность, например, отключить некоторые интеграции
    # или использовать локальные данные вместо облачных.


def filter_and_translate_policy(policy: dict, role: str) -> dict:
    # Какие поля видит каждая роль
    role_access_map = {
        "admin": ["data_storage", "data_encryption", "access_control", "incident_response"],
        "viewer": ["data_encryption", "access_control"],  # допустим viewer видит только шифрование и контроль доступа
    }

    # Словарь для перевода значений на русский
    translations = {
        "unassigned": "не назначено",
        "cloud_provider": "облачный провайдер",
        "restaurant_owner": "владелец ресторана",
    }

    allowed_fields = role_access_map.get(role, [])
    filtered_policy = {}

    for key in allowed_fields:
        value = policy.get(key, "неизвестно")
        filtered_policy[key] = translations.get(value, value)  # переводим или оставляем как есть

    return filtered_policy
