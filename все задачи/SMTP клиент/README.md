## Задача 3

**Формулировка задачи:**

SMTP клиент. На сервера mail, yandex, rambler письма с вложениями должны доходить и быть читабельными.
Для работы клиенту нужен json и .env
```json
{
  "subject": "<Тема>",
  "body": "<Тело>",

  "receivers": [
    "<Список получателей>"
  ],

  "attachments": [
   "<Cписок путей до закрепленных файлов>"
  ]
}
```
```env
MAIL = "<Пусть до json письма>"
LOGIN = "<Логин без домена>"
PASSWORD = "<Пароль>"
HOST_ADDRESS = "smtp.yandex.ru."
PORT = "465"
```


**Переменные окружения, которые могут быть использованы для конфигурации клиента**:

* LOGIN - логин пользователя
* PASSWORD - пароль пользователя
* HOST_ADDRESS - доменное имя или IP-адрес SMTP сервера
* PORT - порт, по которому происходит подключение к серверу

## Пример
```sh
python3 smtp_client.py
```