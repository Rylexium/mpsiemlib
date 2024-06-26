import json
import time
import re
from datetime import datetime
from typing import List

from mpsiemlib.common import ModuleInterface, MPSIEMAuth, LoggingHandler, MPComponents, Settings
from mpsiemlib.common import exec_request


class HealthMonitor(ModuleInterface, LoggingHandler):
    """
    Health monitor module
    """

    __api_global_status = '/api/health_monitoring/v2/total_status'
    __api_checks = '/api/health_monitoring/v2/checks?limit={}&offset={}'
    __api_license_status = '/api/licensing/v2/license_validity'
    __api_agents_status = '/api/components/agent'
    __api_agents_status_new = '/api/v1/scanner_agents'
    __api_kb_status = '/api/v1/knowledgeBase'

    # шаблоны сообщений
    __api_error_pattern_messages_new = "/assets/i18n/ru-RU/navigation.json?{}" # V.25
    __api_error_pattern_messages_old = "/Content/locales/l10n/ru-RU/navigation.json?{}" # V.23 - V.24

    __kb_port = 8091

    def __init__(self, auth: MPSIEMAuth, settings: Settings):
        ModuleInterface.__init__(self, auth, settings)
        LoggingHandler.__init__(self)

        try:
            self.__core_session = auth.connect(MPComponents.CORE)
        except:
            self.__core_session = None
        self.__core_hostname = auth.creds.core_hostname
        self.__core_version = auth.get_core_version()

        try:
            self.__kb_session = auth.connect(MPComponents.KB)
        except:
            self.__kb_session = None

        self.__error_patterns = None

    def get_health_status(self) -> str:
        """
        Получить общее состояние системы

        :return: "ok" - если нет ошибок
        """
        url = f'https://{self.__core_hostname}{self.__api_global_status}'
        r = exec_request(self.__core_session,
                         url,
                         method='GET',
                         timeout=self.settings.connection_timeout)
        response = r.json()
        status = response.get('status')

        self.log.info('status=success, action=get_health_status, msg="Got global status", '
                      'hostname="{}" status="{}"'.format(self.__core_hostname, status))

        return status

    def get_health_errors(self) -> List[dict]:
        """
        Получить список ошибок из семафора.

        :return: Список ошибок или пустой массив, если ошибок нет
        """
        limit = 1000
        offset = 0
        api_url = self.__api_checks.format(limit, offset)
        url = f"https://{self.__core_hostname}{api_url}"
        r = exec_request(self.__core_session,
                         url,
                         method='GET',
                         timeout=self.settings.connection_timeout)
        response = r.json()
        errors = response.get('items')

        ret = []
        for i in errors:
            source = i.get("source") if i.get("source") is not None else {}
            params = i.get("parameters") if i.get("parameters") is not None else {}
            ret.append({"id": i.get("id"),
                        "timestamp": i.get("timestamp"),
                        "status": i.get("status", "").lower(),
                        "type": i.get("type").lower(),
                        "name": source.get("displayName").lower(),
                        "hostname": source.get("hostName"),
                        "ip": source.get("ipAddresses"),
                        "component_name": params.get("componentName"),
                        "component_hostname": params.get("hostName"),
                        "component_ip": params.get("ipAddresses"),
                        "parameters": params,
                        "source": source,
                        "sensitive": i.get("sensitive"),
                        "displayName": source.get('displayName'),
                        "componentName": params.get("componentName"),
                        "hostName": params.get("hostName"),
                        })

        self.log.info('status=success, action=get_health_errors, msg="Got errors", '
                      'hostname="{}" count="{}"'.format(self.__core_hostname, len(errors)))

        return ret

    def get_health_license_status(self) -> dict:
        """
        Получить статус лицензии.

        :return: Dict
        """
        url = f'https://{self.__core_hostname}{self.__api_license_status}'
        r = exec_request(self.__core_session,
                         url,
                         method='GET',
                         timeout=self.settings.connection_timeout)
        response = r.json()
        lic = response.get('license')
        status = {'valid': response.get('validity') == 'valid',
                  'key': lic.get('keyNumber'),
                  'type': lic.get('licenseType'),
                  'granted': lic.get('keyDate'),
                  'expiration': lic.get('expirationDate'),
                  'assets': lic.get('assetsCount')}

        self.log.info('status=success, action=get_health_license_status, msg="Got license status", '
                      'hostname="{}"'.format(self.__core_hostname))

        return status

    def get_health_agents_status(self) -> List[dict]:
        """
        Получить статус агентов.

        :return: Список агентов и их параметры.
        """
        if int(self.__core_version.split('.')[0]) < 25:
            url = f'https://{self.__core_hostname}{self.__api_agents_status}'
        else:
            url = f'https://{self.__core_hostname}{self.__api_agents_status_new}'
        r = exec_request(self.__core_session,
                         url,
                         method='GET',
                         timeout=self.settings.connection_timeout)
        response = r.json()

        agents = []
        for i in response:
            agents.append({
                'id': i.get('id'),
                'name': i.get('name'),
                'hostname': i.get('address'),
                'version': i.get('version'),
                'updates': i.get('availableUpdates'),
                'status': i.get('status'),
                'roles': i.get('roleNames'),
                'ip': i.get('ipAddresses'),
                'platform': i.get('platform'),
                'modules': i.get('modules')
            })

        self.log.info('status=success, action=get_health_agents_status, msg="Got agents status", '
                      'hostname="{}" count="{}"'.format(self.__core_hostname, len(agents)))

        return agents

    def get_health_kb_status(self) -> dict:
        """
        Получить статус обновления VM контента в Core.

        :return: dict.
        """
        url = f'https://{self.__core_hostname}:{self.__kb_port}{self.__api_kb_status}'
        r = exec_request(self.__kb_session,
                         url,
                         method='GET',
                         timeout=self.settings.connection_timeout)
        response = r.json()
        local = response.get('localKnowledgeBase')
        remote = response.get('remoteKnowledgeBase')
        status = {'status': response.get('status'),
                  'local_updated': local.get('lastUpdate'),
                  'local_current_revision': local.get('localRevision'),
                  'local_global_revision': local.get('globalRevision'),
                  'kb_db_name': remote.get('name')}

        self.log.info('status=success, action=get_health_kb_status, msg="Got KB status", '
                      'hostname="{}"'.format(self.__core_hostname))

        return status

    def __humanbytes(self, bytes):
        """Return the given bytes as a human friendly KB, MB, GB, or TB string."""
        B = float(bytes)
        KB = float(1024)
        MB = float(KB ** 2)  # 1,048,576
        GB = float(KB ** 3)  # 1,073,741,824
        TB = float(KB ** 4)  # 1,099,511,627,776

        if B < KB:
            return '{0} {1}'.format(B, 'Байты' if 0 == B > 1 else 'Байт')
        elif KB <= B < MB:
            return '{0:.2f} КБ'.format(B / KB)
        elif MB <= B < GB:
            return '{0:.2f} МБ'.format(B / MB)
        elif GB <= B < TB:
            return '{0:.2f} ГБ'.format(B / GB)
        elif TB <= B:
            return '{0:.2f} ТБ'.format(B / TB)

    def get_error_messages(self) -> list:
        """
        Позволяет получить список сообщений в HealthMonitor'e

        :return: list.
        example returned data:
        [{'time': '2023-09-15T10:18:21.0000000Z', 'status': 'warning', 'displayName': 'Core Deployment Configuration',
        'componentName': 'Update and Configuration Service',
        'message': 'Компонент Update and Configuration Service на узле https://10.0.0.1:9035 недоступен.
        \nОт Core Deployment Configuration\nна узле example.ru (10.0.0.2)'},
        {'time': '2023-11-26T15:44:11.0000000Z', 'status': 'warning', 'displayName': 'SIEM Server correlator',
        'componentName': None, 'message': 'Некоторые правила корреляции были приостановлены, поскольку срабатывали слишком часто.
        \nОт SIEM Server correlator\nна узле primer.example.ru (10.0.0.3)'}]
        """

        if self.get_health_status() == "ok":
            return [{"time": datetime.utcfromtimestamp(time.time()).strftime('%Y-%m-%dT%H:%M:%S.0000000Z'),
                     "status": "ok", "message": "Сообщений нет. Система работает нормально"}]

        items = self.get_health_errors()
        if self.__error_patterns is None:  # в кеше нет списка шаблонов
            # time.time() потому что данные могут быть кешированы и дабы избежать добавляется текущие время для макс актуальности
            api_url = self.__api_error_pattern_messages_new.format(time.time()) \
                if int(self.__core_version.split('.')[0]) >= 25 \
                else self.__api_error_pattern_messages_old.format(time.time())
            url = f"https://{self.__core_hostname}{api_url}"
            r = exec_request(self.__core_session, url, method='GET', timeout=self.settings.connection_timeout)
            self.__error_patterns = json.loads(str(r.text).encode('utf-8'))  # тут могут быть траблы с кодировкой, поэтому utf-8
            self.__error_patterns = {
                pattern.replace('_', '').replace('-', '').replace('.', '').lower(): self.__error_patterns[pattern]
                for pattern in self.__error_patterns}

        prefix, rows = "navigationnotificationsmessage", []
        for item in items:
            type_err, type_err_sensitive = item['type'].replace('_', '').replace('-', '').replace('.', '').lower(), ""
            if item['sensitive']:
                type_err_sensitive = f"{type_err}sensitive"

            # если существует ключ с добавлением sensitive, то берём этот шаблон, иначе без sensitive
            pattern = self.__error_patterns[f"{prefix}{type_err_sensitive}"
            if f"{prefix}{type_err_sensitive}" in self.__error_patterns.keys()
            else f"{prefix}{type_err}"]

            # замением все значения типа {value} в шаблоне. Нужные значения хранятся в виде json по ключу parameters
            params = item.get("parameters")
            for param in params:
                if param == "ipAddresses":
                    params[param] = f" ({', '.join([adr for adr in params[param]])})" if len(params[param]) > 0 else ""


                # {{threshold | bytes}}     v.23-v.24
                # {threshold, bytes}        v.25-v.26
                if param == 'threshold':
                    params[param] = self.__humanbytes(params[param])
                    pattern = pattern.replace("{{" + str(param) + " | bytes}}", params[param])\
                        .replace("{" + str(param) + " | bytes}", params[param]) \
                        .replace("{{" + str(param) + ", bytes}}", params[param]) \
                        .replace("{" + str(param) + ", bytes}", params[param]) \
                        .replace("{{" + str(param) + " , bytes}}", params[param]) \
                        .replace("{" + str(param) + " , bytes}", params[param])

                pattern = pattern.replace("{" + param + "}", str(params[param]))\
                    .replace("{" + str(params[param]) + "}", str(params[param]))

            # Далее танцы с бубном, потому что эти значения могут быть, а могут и не быть, поэтому если они есть, то будут добавлены
            if item.get('source') is not None:
                if item['source'].get('displayName') is not None:
                    pattern += f"\nОт {item['source']['displayName']}"
                if item['source'].get("hostName") is not None:
                    addresses = ""
                    if item['source'].get('ipAddresses') is not None and len(item['source']['ipAddresses']) > 0:
                        addresses = ', '.join([adr for adr in item['source']['ipAddresses']])
                    pattern += f"\nна узле {item['source']['hostName']}"
                    if addresses != "":
                        pattern += f" ({addresses})"

            union = set(re.findall("\{([^}]+)\}", pattern)).union(re.findall("\{{([^}]+)\}}", pattern))
            for field in union:
                pattern = pattern.replace(field, '')

            rows.append({"time": item['timestamp'], "status": item['status'], "displayName": item['displayName'],
                         "componentName": item['componentName'],
                         "message": re.sub("\s\s+" , " ",
                                           pattern.replace('{', '').replace('}', '')
                                           .replace('| bytes', '').replace(', bytes', ''))})

        return rows

    def close(self):
        if self.__core_session is not None:
            self.__core_session.close()
