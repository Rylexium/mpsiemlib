from mpsiemlib.common import ModuleInterface, MPSIEMAuth, LoggingHandler, MPComponents, Settings
from mpsiemlib.common import exec_request


class Filters(ModuleInterface, LoggingHandler):
    """
    Filters module
    """

    __api_filters_list = '/api/v2/events/filters_hierarchy'
    __api_filter_info = '/api/v2/events/filters/{}'
    __api_folders = '/api/v2/events/folders'
    __api_filters = '/api/v2/events/filters'

    __api_filter_info_v3 = "/api/v3/events/filters/{}"

    def __init__(self, auth: MPSIEMAuth, settings: Settings):
        ModuleInterface.__init__(self, auth, settings)
        LoggingHandler.__init__(self)
        self.__core_session = auth.connect(MPComponents.CORE)
        self.__core_hostname = auth.creds.core_hostname
        self.__folders = {}
        self.__filters = {}
        self.log.debug('status=success, action=prepare, msg="Filters Module init"')

    def get_folders_list(self, is_force_update=False) -> dict:
        """
        Получить список всех папок с фильтрами

        :return: {"id": {"parent_id": "value", "name": "value", "source": "value"}}
        """
        if len(self.__folders) != 0 and not is_force_update:
            return self.__folders

        url = f'https://{self.__core_hostname}{self.__api_filters_list}'

        r = exec_request(self.__core_session,
                         url,
                         method='GET',
                         timeout=self.settings.connection_timeout)
        filters = r.json()

        self.__iterate_folders_tree(filters.get("roots"))

        self.log.info('status=success, action=get_folders_list, msg="Got {} folders", '
                      'hostname="{}"'.format(len(self.__folders), self.__core_hostname))

        return self.__folders

    def get_filters_list(self) -> dict:
        """
        Получить список всех фильтров

        :return: {"id": {"folder_id": "value", "name": "value", "source": "value"}}
        """
        if len(self.__filters) != 0:
            return self.__filters

        # папки и фильтры лежат в одной структуре и парсятся совместно
        self.get_folders_list()

        self.log.info('status=success, action=get_filters_list, msg="Got {} filters", '
                      'hostname="{}"'.format(len(self.__filters), self.__core_hostname))

        return self.__filters

    def __iterate_folders_tree(self, root_node, parent_id=None):
        for i in root_node:
            node_id = i.get('id')
            node_name = i.get('name')
            node_source = i.get('meta', {}).get('source')
            if i.get('type') == 'filter_node':
                self.__filters[node_id] = {'folder_id': parent_id,
                                           'name': node_name,
                                           'source': node_source}
                continue
            if i.get('type') == 'folder_node':
                self.__folders[node_id] = {'parent_id': parent_id,
                                           'name': node_name,
                                           'source': node_source}
                node_children = i.get('children')
                if node_children is not None and len(node_children) != 0:
                    self.__iterate_folders_tree(node_children, node_id)

    def get_filter_info(self, filter_id: str) -> dict:
        """
        Получить информацию по фильтру

        :param filter_id: ID фильтра
        :return: {"param1": "value", "param2": "value"}
        """
        api_url = self.__api_filter_info.format(filter_id)
        url = f'https://{self.__core_hostname}{api_url}'

        r = exec_request(self.__core_session,
                         url,
                         method='GET',
                         timeout=self.settings.connection_timeout)
        filters = r.json()

        self.log.info('status=success, action=get_filter_info, msg="Got info for filter {}", '
                      'hostname="{}"'.format(filter_id, self.__core_hostname))

        return {'name': filters.get('name'),
                'folder_id': filters.get('folderId'),
                'removed': filters.get('isRemoved'),
                'source': filters.get('source'),
                'query': {'select': filters.get('select'),
                          'where': filters.get('where'),
                          'group': filters.get('groupBy'),
                          'order': filters.get('groupBy'),
                          'aggregate': filters.get('aggregateBy'),
                          'distribute': filters.get('distributeBy'),
                          'top': filters.get('top'),
                          'aliases': filters.get('aliases')}
                }

    def get_filter_info_by_name(self, filter_name):
        """
        По имени возвращает информацию первого найденного фильтра
        filter_name : имя фильтра в SIEM
        """
        filters = self.get_filters_list()
        for uuid_filter in filters:
            if filters[uuid_filter]['name'] == filter_name:
                return self.get_filter_info(uuid_filter)
        return None

    def get_folder_by_name(self, folder_name):
        """
        По имени возвращает информацию первый найденный директории
        folder_name : имя фильтра в SIEM
        """
        folders = self.get_folders_list()
        for uuid_folder in folders:
            if folders[uuid_folder]['name'] == folder_name:
                folders[uuid_folder]['uuid'] = uuid_folder
                return folders[uuid_folder]
        return None

    def create_folder_by_name(self, folder_parent_name, folder_name):
        folder_parent_id = self.get_folder_by_name(folder_parent_name)['uuid']
        return self.create_folder_by_id(folder_parent_id, folder_name)

    def create_folder_by_id(self, folder_parent_id, folder_name):
        url = f'https://{self.__core_hostname}{self.__api_folders}'
        r = exec_request(self.__core_session,
                         url,
                         method='POST',
                         timeout=self.settings.connection_timeout,
                         json={"parentId": folder_parent_id, "name": folder_name})
        self.get_folders_list(is_force_update=True)
        return r.json()

    def delete_folder_by_name(self, folder_name):
        folder_id = self.get_folder_by_name(folder_name)['uuid']
        return self.delete_folder_by_id(folder_id)

    def delete_folder_by_id(self, folder_id):
        url = f'https://{self.__core_hostname}{self.__api_folders}/{folder_id}'
        r = exec_request(self.__core_session,
                         url,
                         method='DELETE',
                         timeout=self.settings.connection_timeout)
        self.get_folders_list(is_force_update=True)
        return r.status_code == 200

    def create_filter_by_folder_name(self, filter, folder_name):
        folder_id = self.get_folder_by_name(folder_name)
        return self.create_filter_by_folder_id(filter, folder_id)

    def create_filter_by_folder_id(self, filter, folder_id):
        url = f'https://{self.__core_hostname}{self.__api_filters}'
        filter['folderId'] = folder_id
        r = exec_request(self.__core_session,
                         url,
                         method='POST',
                         timeout=self.settings.connection_timeout,
                         json=filter)
        self.get_folders_list(is_force_update=True)
        return r.json()

    def get_filter_info_v3(self, filter_id):
        url = f'https://{self.__core_hostname}{self.__api_filter_info_v3.format(filter_id)}'

        r = exec_request(self.__core_session, url, method='GET', timeout=self.settings.connection_timeout)
        filter_info = r.json()

        self.log.info('status=success, action=get_filter_info, msg="Got info for filter {}", '
                      'hostname="{}"'.format(filter_id, self.__core_hostname))

        return filter_info

    def close(self):
        if self.__core_session is not None:
            self.__core_session.close()
