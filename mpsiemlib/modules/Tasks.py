import json
import re
import time
import traceback
from typing import Optional
from uuid import UUID

from mpsiemlib.common import ModuleInterface, MPSIEMAuth, LoggingHandler, MPComponents, Settings
from mpsiemlib.common import exec_request


class Tasks(ModuleInterface, LoggingHandler):
    """
    Tasks module
    """

    __api_agents_list = '/api/v1/scanner_agents'
    __api_modules_list = '/api/v1/scanner_modules'
    __api_profiles_list = ''
    __api_profiles_list_old = '/api/v2/scanner_profiles'  # R23
    __api_profiles_list_new = '/api/scanning/v3/scanner_profiles'  # R24
    __api_transports_list = '/api/v1/scanner_metatransports'
    __api_credentials_list = '/api/v3/credentials'
    __api_tasks_list = '/api/scanning/v3/scanner_tasks?additionalFilter=all&mainFilter=all'
    __api_task_info = '/api/scanning/v3/scanner_tasks/{}'
    __api_create_task = '/api/scanning/v3/scanner_tasks'
    __api_task_run_history = '/api/scanning/v2/scanner_tasks/{}/runs?limit={}'
    __api_jobs_list = '/api/scanning/v2/runs/{}/jobs?limit={}'
    __api_task_start = '/api/scanning/v3/scanner_tasks/{}/start'
    __api_task_stop = '/api/scanning/v3/scanner_tasks/{}/stop'

    __api_error_messages = "/api/scanning/v2/jobs/{}/job_errors?limit={}&offset={}&orderBy=occurredAt+desc"
    __api_task_run_history_with_errors = "/api/scanning/v2/scanner_tasks/{}/runs?limit={}&withErrors=false"
    __api_fail_job = "/api/scanning/v2/runs/{}/jobs?limit=50&orderby=startedAt+desc"
    __api_error_pattern_messages_new = "/ng1/Content/locales/l10n/ru-RU/external/scan-errors-log.json?{}"  # R25
    __api_error_pattern_messages_old = "/Content/locales/l10n/ru-RU/external/scan-errors-log.json?{}"  # R23 - R24
    __api_credentials_login_password = "/api/v3/credentials/login_passwords"  # v25
    __api_credentials_certificate = "/api/v3/credentials/certificates"  # v25
    __api_credentials_password_only = "/api/v3/credentials/passwords_only"

    def __init__(self, auth: MPSIEMAuth, settings: Settings):
        ModuleInterface.__init__(self, auth, settings)
        LoggingHandler.__init__(self)
        self.__core_session = auth.connect(MPComponents.CORE)
        self.__core_hostname = auth.creds.core_hostname
        self.__core_version = auth.get_core_version()
        self.__agents = {}
        self.__modules = {}
        self.__profiles = {}
        self.__transports = {}
        self.__credentials = {}
        self.__tasks = {}
        self.__error_patterns = None

        if int(self.__core_version.split('.')[0]) == 23:
            self.__api_profiles_list = self.__api_profiles_list_old
        else:
            self.__api_profiles_list = self.__api_profiles_list_new

        self.log.debug('status=success, action=prepare, msg="Tasks Module init"')

    def start_task(self, task_id):
        if self.get_task_status(task_id) == 'finished':
            self.__manipulate_task(task_id, 'start')
        else:
            self.log.warning('status=failed, action=manipulate_task, msg="Task {} already started or pending", '
                             'hostname="{}"'.format(task_id, self.__core_hostname))

    def stop_task(self, task_id):
        if self.get_task_status(task_id) == 'running':
            self.__manipulate_task(task_id, 'stop')
        else:
            self.log.warning('status=failed, action=manipulate_task, msg="Task {} already stopped or pending", '
                             'hostname="{}"'.format(task_id, self.__core_hostname))

    def get_task_status(self, task_id):
        self.get_tasks_list(do_refresh=True)
        return self.__tasks[task_id]['status']

    def __manipulate_task(self, task_id, control="stop"):
        api_url = (self.__api_task_start if control == "start" else self.__api_task_stop).format(task_id)
        url = f'https://{self.__core_hostname}{api_url}'
        r = exec_request(self.__core_session,
                         url,
                         method='POST',
                         timeout=self.settings.connection_timeout)
        run_id = None
        if control == 'start':
            response = r.json()
            run_id = response.get('id')
            if run_id is None:
                raise Exception('Task manipulation error')

        self.log.info('status=success, action=manipulate_task, msg="{} task {}", '
                      'hostname="{}"'.format(control, task_id, self.__core_hostname))

        return run_id

    def get_agents_list(self, do_refresh=False) -> dict:
        """
        Получить список всех агентов.
        Есть еще одно API в HealthMonitor

        :return:
        """
        if len(self.__agents) != 0 and not do_refresh:
            return self.__agents

        self.__agents.clear()

        url = f'https://{self.__core_hostname}{self.__api_agents_list}'
        r = exec_request(self.__core_session,
                         url,
                         method='GET',
                         timeout=self.settings.connection_timeout)
        response = r.json()

        for i in response:
            self.__agents[i.get('id')] = {'name': i.get('name'),
                                          'hostname': i.get('address'),
                                          'version': i.get('version'),
                                          'status': i.get('status'),
                                          'modules': i.get('modules')
                                          }

        self.log.info('status=success, action=get_agents_list, msg="Got agents list", '
                      'hostname="{}", count={}'.format(self.__core_hostname, len(self.__agents)))

        return self.__agents

    def get_modules_list(self, do_refresh=False) -> dict:
        """
        Получить список всех доступных модулей.
        Информация урезана.

        :return:
        """
        if len(self.__modules) != 0 and not do_refresh:
            return self.__modules

        self.__modules.clear()

        url = f'https://{self.__core_hostname}{self.__api_modules_list}'
        r = exec_request(self.__core_session,
                         url,
                         method='GET',
                         timeout=self.settings.connection_timeout)
        response = r.json()

        for i in response:
            self.__modules[i.get('id')] = {'name': i.get('name'),
                                           'type': i.get('outputType').lower(),
                                           }

        self.log.info('status=success, action=get_modules_list, msg="Got credentials list", '
                      'hostname="{}", count={}'.format(self.__core_hostname, len(self.__modules)))

        return self.__modules

    def get_profiles_list(self, do_refresh=False) -> dict:
        """
        Получить список всех профилей.
        Информация урезана.

        :return:
        """
        if len(self.__profiles) != 0 and not do_refresh:
            return self.__profiles

        self.__profiles.clear()

        url = f'https://{self.__core_hostname}{self.__api_profiles_list}'
        r = exec_request(self.__core_session,
                         url,
                         method='GET',
                         timeout=self.settings.connection_timeout)
        response = r.json()

        # почему-то ID выглядит как "{8406e439-9402-4fad-893e-583009d8e797}" - в R23
        self.__profiles = {profile.get('id', '').replace('{', '').replace('}', ''): profile for profile in response}

        self.log.info('status=success, action=get_profiles_list, msg="Got profiles list", '
                      'hostname="{}", count={}'.format(self.__core_hostname, len(self.__profiles)))

        return self.__profiles

    def get_transports_list(self, do_refresh=False) -> dict:
        """
        Получить список всех транспортов.
        Информация урезана.

        :return:
        """

        if "23." not in self.__core_version:
            raise NotImplementedError(f'Transports list API deprecated on {self.__core_version}')

        if len(self.__transports) != 0 and not do_refresh:
            return self.__transports

        self.__transports.clear()

        url = f'https://{self.__core_hostname}{self.__api_transports_list}'
        r = exec_request(self.__core_session,
                         url,
                         method='GET',
                         timeout=self.settings.connection_timeout)
        response = r.json()

        for i in response:
            self.__transports[i.get('id')] = {'name': i.get('name')}

        self.log.info('status=success, action=get_transports_list, msg="Got transports list", '
                      'hostname="{}", count={}'.format(self.__core_hostname, len(self.__transports)))

        return self.__transports

    def get_credentials_list(self, do_refresh=False) -> dict:
        """
        Получить список всех учетных записей для подключения к источникам.
        Информация урезана.

        :return:
        """
        if len(self.__credentials) != 0 and not do_refresh:
            return self.__credentials

        self.__transports.clear()

        url = f'https://{self.__core_hostname}{self.__api_credentials_list}'
        r = exec_request(self.__core_session,
                         url,
                         method='GET',
                         timeout=self.settings.connection_timeout)
        response = r.json()

        for i in response:
            self.__credentials[i.get('id')] = {'name': i.get('name'),
                                               'type': i.get('type'),
                                               'description': i.get('description'),
                                               'credential_tags': i.get('credentialTags'),
                                               'transports': i.get('metatransports'),
                                               }

        self.log.info('status=success, action=get_credentials_list, msg="Got credentials list", '
                      'hostname="{}", count={}'.format(self.__core_hostname, len(self.__credentials)))

        return self.__credentials

    def get_tasks_list(self, do_refresh=False) -> dict:
        """
        Получить список всех задач.
        Информация урезана.

        :return:
        """
        if len(self.__tasks) != 0 and not do_refresh:
            return self.__tasks

        url = f'https://{self.__core_hostname}{self.__api_tasks_list}'
        r = exec_request(self.__core_session,
                         url,
                         method='GET',
                         timeout=self.settings.connection_timeout)
        response = r.json()

        for i in response:
            profile = {'id': i.get('profile', {}).get('id').replace('{', '').replace('}', ''),
                       'name': i.get('name')}
            self.__tasks[i.get('id')] = {'name': i.get('name'),
                                         'agent': i.get('agent'),
                                         'scope': i.get('scope'),
                                         'profile': profile,
                                         'module': i.get('module'),
                                         'transports': i.get('metatransports'),
                                         'status': i.get('status'),
                                         'created': i.get('created'),
                                         'run_last': i.get('lastRun'),
                                         'run_last_error_level': i.get('lastRunErrorLevel'),
                                         'run_last_error': i.get('lastRunError'),
                                         'target_include': i.get('include'),
                                         'target_exclude': i.get('exclude'),
                                         "is_fqdn_priority": i.get("isFqdnPriority"),
                                         'status_validation': i.get('validationState'),
                                         'host_discovery': i.get('hostDiscovery'),
                                         'bookmarks': i.get('hasBookmarks'),
                                         'credentials': i.get('credentials'),
                                         'trigger_parameters': i.get('triggerParameters')
                                         }

        self.log.info('status=success, action=get_tasks_list, msg="Got task list", '
                      'hostname="{}", count={}'.format(self.__core_hostname, len(self.__tasks)))

        return self.__tasks

    def get_task_info(self, task_id: str) -> dict:
        """
        Получить информацию по задаче

        :return:
        """
        if len(self.__tasks) == 0:
            self.get_tasks_list()

        api_url = self.__api_task_info.format(task_id)
        url = f'https://{self.__core_hostname}{api_url}'
        r = exec_request(self.__core_session,
                         url,
                         method='GET',
                         timeout=self.settings.connection_timeout)
        r = r.json()

        task = self.__tasks.get(task_id)
        if task is None:
            raise Exception(f'Task {task_id} not found')

        task['parameters'] = r.get('parameters')

        self.log.info('status=success, action=get_task_info, msg="Got info for task {}", '
                      'hostname="{}"'.format(task_id, self.__core_hostname))

        return r

    def get_default_audit_task_params(self) -> dict:
        params = {'name': 'task_name',
                  'scope': '00000000-0000-0000-0000-000000000005',
                  'profile': 'use get_profiles_list() to get profile UUID',
                  'agent': 'use get_agents_list() to get agent UUID',
                  'overrides': {'transports': {'terminal': {'ssh': {'connection': {
                      'auth': {'ref_value': 'use get_credentials_list() to get credentials UUID',
                               'ref_type': 'credential'}, 'privilege_elevation': {'sudo': {
                          'auth': {'ref_value': 'use get_credentials_list() to get credentials UUID',
                                   'ref_type': 'credential'}}}}}}}},
                  'hostDiscovery': {'enabled': 'false', 'profile': 'null'},
                  'include': {'targets': ['list', 'of', 'ip', 'addresses', 'to', 'scan'], 'assets': [],
                              'assetsGroups': []}, 'exclude': {'targets': [], 'assets': [], 'assetsGroups': []},
                  'triggerParameters': {'isEnabled': 'false', 'fromDate': '2023-01-18T14:46:02.717Z',
                                        'timeZone': '+03:00', 'type': 'Daily', 'atTime': '09:00:00',
                                        'daysOfWeek': ['monday', 'tuesday', 'wednesday', 'thursday', 'friday',
                                                       'saturday', 'sunday']}}
        return params

    def get_default_syslog_task_params(self) -> dict:
        params = {'name': 'task_name',
                  'scope': '00000000-0000-0000-0000-000000000005',
                  'profile': 'use get_profiles_list() to get profile UUID',
                  'agent': 'use get_agents_list() to get agent UUID',
                  'overrides': {},
                  'hostDiscovery': {'enabled': 'false', 'profile': 'null'},
                  'include': {'targets': [], 'assets': [], 'assetsGroups': []},
                  'exclude': {'targets': [], 'assets': [], 'assetsGroups': []},
                  'triggerParameters': {'isEnabled': 'false', 'fromDate': '2023-02-04T12:36:01.663Z',
                                        'timeZone': '+03:00', 'type': 'Daily', 'atTime': '09:00:00',
                                        'daysOfWeek': ['monday', 'tuesday', 'wednesday', 'thursday', 'friday',
                                                       'saturday', 'sunday']}}
        return params

    def create_task(self, params: dict) -> dict:
        """
        Создать задачу

        :return: task_id: ID созданной задачи
        """

        api_url = self.__api_create_task
        url = f'https://{self.__core_hostname}{api_url}'
        r = exec_request(self.__core_session,
                         url,
                         method='POST',
                         timeout=self.settings.connection_timeout,
                         json=params)
        r = r.json()
        task_id = r.get('id')
        return task_id

    def delete_task(self, task_id) -> int:
        """
        Удалить задачу
        :param task_id: ID задачи
        :return: status_code: если вернулось 204, знаичт задача удалена
        """

        api_url = self.__api_task_info.format(task_id)
        url = f'https://{self.__core_hostname}{api_url}'
        r = exec_request(self.__core_session,
                         url,
                         method='DELETE',
                         timeout=self.settings.connection_timeout)
        return r.status_code

    def get_jobs_list(self, task_id: str, limit: Optional[int] = 1000) -> dict:
        """
        Получить список всех подзадач у задачи
        Информация урезана.

        :param task_id: ID задачи
        :param limit: Кол-во запрошенных подзадач
        :return: {job_id: {"param1": "value"}}
        """

        # сначала надо получить историю запусков, а потом ID истории получить job-ы
        api_url = self.__api_task_run_history.format(task_id, limit)
        url = f'https://{self.__core_hostname}{api_url}'
        r = exec_request(self.__core_session,
                         url,
                         method='GET',
                         timeout=self.settings.connection_timeout)
        response = r.json()

        if response.get('items') is None:
            raise Exception('No items in response')

        # ищем запущенный экземпляр задачи в истории
        run_id = None
        for i in response.get('items'):
            if i.get('finishedAt') is None:
                run_id = i.get('id')
                break

        if run_id is None:
            self.log.info('status=success, action=get_jobs_list, msg="Running tasks not found", '
                          'hostname="{}"'.format(self.__core_hostname))

            return {}

        api_url = self.__api_jobs_list.format(run_id, limit)
        url = f'https://{self.__core_hostname}{api_url}'
        r = exec_request(self.__core_session,
                         url,
                         method='GET',
                         timeout=self.settings.connection_timeout)
        response = r.json()

        if response.get('items') is None:
            raise Exception('No items in response')

        jobs = {}
        for i in response.get('items'):
            jobs[i.get('id')] = {'status': i.get('status'),
                                 'status_error': i.get('errorStatus'),
                                 'started': i.get('startedAt'),
                                 'finished': i.get('finishedAt'),
                                 'agent': i.get('agent'),
                                 'targets': i.get('targets')
                                 }

        self.log.info('status=success, action=get_jobs_list, msg="Got {} jobs for task {}", '
                      'hostname="{}"'.format(len(jobs), task_id, self.__core_hostname))

        return jobs

    def get_history_job_list(self, task_id: str, limit: Optional[int] = 1000) -> dict:
        """
        Позволяет получить список всех runner'ов у задачи по task_id.

        Args:
            task_id : uuid задачи

        """
        api_url = self.__api_task_run_history_with_errors.format(task_id, limit)
        url = "https://{}{}".format(self.__core_hostname, api_url)
        r = exec_request(self.__core_session,
                         url,
                         method='GET',
                         timeout=self.settings.connection_timeout)
        response = r.json()
        if response.get("items") is None:
            raise Exception("No items in response")
        jobs = {item.get("id"): {
            "status": item.get("status"),
            "startedAt": item.get("startedAt"),
            "finishedAt": item.get("finishedAt"),
            "jobCount": item.get("jobCount"),
            "id": item['startedBy'].get('id') if item.get('startedBy') is not None else None,
            "login": item['startedBy'].get("login") if item.get('startedBy') is not None else None,
            "firstName": item['startedBy'].get("firstName") if item.get('startedBy') is not None else None,
            "lastName": item['startedBy'].get("lastName") if item.get('startedBy') is not None else None,
            "stoppedBy": item.get("stoppedBy"),
            "errorStatus": item.get("errorStatus")
        } for item in response.get("items")}

        return jobs

    def get_all_jobs(self, run_id):
        return self.__get_api_url(self.__api_fail_job.format(run_id))

    def get_error_message(self, subtask_id, limit=20, offset=0):
        """
        Позволяет получить список сообщений об ошибке у конкретной подзадачи.

        subtask_id : uuid подзадачи у раннера в задаче
        """
        self.settings.connection_timeout = 180  # увеличиваю timeout

        # задача состоит из одной подзадачи если =0, иначе много подзадач
        items = self.__get_api_url(self.__api_error_messages.format(subtask_id, limit, offset))
        if self.__error_patterns is None:
            api_url = self.__api_error_pattern_messages_new.format(time.time()) \
                if int(self.__core_version.split('.')[0]) >= 25 \
                else self.__api_error_pattern_messages_old.format(time.time())
            url = f"https://{self.__core_hostname}{api_url}"
            r = exec_request(self.__core_session, url, method='GET', timeout=self.settings.connection_timeout)
            tmp_error_patterns = json.loads(str(r.text).encode('utf-8'))
            self.__error_patterns = {
                key.replace('_', '').replace('-', '').replace('.', '').lower(): tmp_error_patterns[key]
                for key in tmp_error_patterns.keys()}
        prefix, rows = "scanerrorslogmessageerroritemtext", []
        for item in items:
            params = item.get('parameters')
            type_err = item['type'].replace('_', '').replace('-', '').replace('.', '').lower()
            if f"{prefix}{type_err}" not in self.__error_patterns.keys() or params is None:
                pattern = f"Произошла ошибка: {item['type']}"
            else:
                pattern = self.__error_patterns[f"{prefix}{type_err}"]
                for param in params:
                    pattern = pattern.replace('{{' + param + '}}', str(params[param]))
            rows.append({"time": item['occurredAt'], "source": item['sourceName'],
                         "message": re.sub("\s\s+", " ", pattern)})

        return rows

    def __get_api_url(self, api_url):
        """
        По сути обычный wrapper для избежания дубликации кода.
        """
        url = f"https://{self.__core_hostname}{api_url}"
        r = exec_request(self.__core_session, url, method='GET', timeout=self.settings.connection_timeout)
        response = r.json()
        if response.get("items") is None:
            raise Exception("No items in response")

        return response.get("items")

    def get_last_error_message_by_task_name_and_targets(self, task_name, target, limit=50, offset=0):
        """
        Позволяет получить список сообщений об ошибке,
        указав имя задачи (найдёт первую, которая соответствует имени) и адрес источника.

        Args:
            task_name : имя задачи
            target : адрес или fqdn источника
        """
        tasks = self.get_tasks_list()
        history_job_list, job_list = None, None
        for uuid_task in tasks:  # находим нужную задачу по имени
            if tasks[uuid_task]['name'] == task_name:
                history_job_list = self.get_history_job_list(uuid_task,
                                                             limit)  # получения списка runner'ов (история перезапуска задачи)
                job_list = self.get_all_jobs(
                    list(history_job_list.keys())[0])  # берём последний runner и получаем список подзадач у него
                break
        info_job = None
        for job in job_list:  # в подзадачах ищем адрес источника
            if target in job['targets']:
                info_job = job
                break
        return self.get_error_message(info_job['id'], limit=limit, offset=offset)

    def get_last_error_message_by_task_name(self, task_name, limit=50, offset=0):
        """
        Позволяет получить список сообщений об ошибке у первой подзадачи,
        указав имя задачи (найдёт первую, которая соответствует имени).

        Args:
            task_name : имя задачи
        """
        tasks = self.get_tasks_list()
        history_job_list, job_list = None, None
        for uuid_task in tasks:
            if tasks[uuid_task]['name'] == task_name:  # находим нужную задачу по имени
                history_job_list = self.get_history_job_list(uuid_task,
                                                             limit)  # получения списка runner'ов (история перезапуска задачи)
                job_list = self.get_all_jobs(
                    list(history_job_list.keys())[0])  # берём последний runner и получаем список подзадач у него
                break
        return self.get_error_message(job_list[0]['id'], limit=limit, offset=offset)  # берём самую первую подзадачу

    def get_last_error_message_by_task_id(self, task_id, limit=50, offset=0):
        """
        Позволяет получить список сообщений об ошибке у первой подзадачи,
        указав uuid задачи (найдёт первую, которая соответствует имени).

        Args:
            task_id : uuid задачи
        """
        history_job_list = self.get_history_job_list(task_id,
                                                     limit)  # получения списка runner'ов (история перезапуска задачи)
        job_list = self.get_all_jobs(
            list(history_job_list.keys())[0])  # берём последний runner и получаем список подзадач у него
        return self.get_error_message(job_list[0]['id'], limit=limit, offset=offset)  # берём самую первую подзадачу

    def get_last_error_message_by_task_id_and_targets(self, task_id, target, limit=50, offset=0):
        """
        Позволяет получить список сообщений об ошибке,
        указав uuid задачи (найдёт первую, которая соответствует имени) и адрес источника.

        Args:
            task_id : имя задачи
            target : адрес или fqdn источника
        """
        history_job_list = self.get_history_job_list(task_id,
                                                     limit)  # получения списка runner'ов (история перезапуска задачи)
        job_list = self.get_all_jobs(
            list(history_job_list.keys())[0])  # берём последний runner и получаем список подзадач у него
        info_job = None
        for job in job_list:
            if target in job['targets']:  # в подзадачах ищем адрес источника
                info_job = job
                break
        return self.get_error_message(info_job['id'], limit=limit, offset=offset)

    def get_last_error_message_job_id(self, job_id, limit=50, offset=0):
        """
        Позволяет получить список сообщений об ошибке,
        указав uuid подзадачи, взяв из runner'a.

        Args:
            job_id : uuid подзадачи
       """
        return self.get_error_message(job_id, limit=limit, offset=offset)

    def get_profile_info(self, profile_id):
        if not self.__is_uuid(profile_id):
            return None

        __url_api_profile = None
        if int(self.__core_version.split('.')[0]) == 23:
            self.__api_profiles_list = self.__api_profiles_list_old
        else:
            self.__api_profiles_list = self.__api_profiles_list_new

        url = f"https://{self.__core_hostname}{self.__api_profiles_list_new}/{profile_id}"
        r = exec_request(self.__core_session,
                         url,
                         method='GET',
                         timeout=self.settings.connection_timeout)
        response = r.json()
        return response

    def post_profile_info(self, name: str, description: str, base_profile_id: str, base_profile_name: str,
                          module_name: str, profile: str, profiles, overrides):
        url = f"https://{self.__core_hostname}{self.__api_profiles_list}"

        params = {
            "name": name,
            "description": description,
            "baseProfileId": base_profile_id,
            "baseProfileName": base_profile_name,
            "moduleName": module_name,
            "profile": profile, #moduleId
            "overrides": overrides
        }
        r = exec_request(self.__core_session, url, method="POST", json=params)
        response = r.json()
        return response

    def add_login_password_credentials(self, name: str, login: str, password: str, domain: str, description: str,
                                       credential_tags: list):
        url = f"https://{self.__core_hostname}{self.__api_credentials_login_password}"
        r = exec_request(self.__core_session, url,
                         method="POST", timeout=self.settings.connection_timeout,
                         json={
                             "credentialTags": credential_tags,
                             "description": description,
                             "domain": domain,
                             "login": login,
                             "name": name,
                             "password": password
                         })
        response = r.json()
        return response.get("id")

    def add_certificate_credentials(self, name: str, login: str, certificate: str, description: str,
                                    credential_tags: list):
        url = f"https://{self.__core_hostname}{self.__api_credentials_certificate}"
        r = exec_request(self.__core_session, url,
                         method="POST", timeout=self.settings.connection_timeout,
                         json={
                             "credentialTags": credential_tags,
                             "description": description,
                             "login": login,
                             "name": name,
                             "certificate": certificate
                         })
        response = r.json()
        return response.get("id")

    def add_password_only_credentials(self, name: str, password: str, description: str, credential_tags: list):
        url = f"https://{self.__core_hostname}{self.__api_credentials_password_only}"
        r = exec_request(self.__core_session, url,
                         method="POST", timeout=self.settings.connection_timeout,
                         json={
                             "credentialTags": credential_tags,
                             "description": description,
                             "name": name,
                             "password": password
                         })
        response = r.json()
        return response.get("id")

    def __wrapper_get_credentials(self, api_url, credential_id):
        if not self.__is_uuid(credential_id):
            return None

        url = f"https://{self.__core_hostname}{api_url}/{credential_id}"
        r = exec_request(self.__core_session, url, method="GET", timeout=self.settings.connection_timeout)
        return r.json()

    def get_credentials_login_password(self, credential_id):
        return self.__wrapper_get_credentials(self.__api_credentials_login_password, credential_id)

    def get_credentials_certificate(self, credential_id):
        return self.__wrapper_get_credentials(self.__api_credentials_certificate, credential_id)

    def get_credentials_password_only(self, credential_id):
        return self.__wrapper_get_credentials(self.__api_credentials_password_only, credential_id)

    def delete_credentials(self, credential_id):
        if not self.__is_uuid(credential_id):
            return None

        url = f"https://{self.__core_hostname}{self.__api_credentials_login_password}/{credential_id}"
        r = exec_request(self.__core_session, url, method="DELETE", timeout=self.settings.connection_timeout)
        response = r.json()
        return response

    @staticmethod
    def __is_uuid(value_uuid):
        try:
            return str(UUID(value_uuid)) == value_uuid
        except:
            return False

    def close(self):
        if self.__core_session is not None:
            self.__core_session.close()
