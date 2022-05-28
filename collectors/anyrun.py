import json
import random
import shelve
from functools import cached_property
from io import BytesIO
from zipfile import ZipFile

import requests
import utils
from websocket import WebSocket


class AnyRunTask:
    _ws_base_url: str = 'wss://app.any.run/sockjs'
    _content_base_url: str = 'https://content.any.run/tasks/{task_uuid}/download/files/{object_id}'
    _default_zip_password: bytes = b'infected'

    _headers: dict[str, str] = {
        'User-Agent': 'Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/101.0.4951.67 Safari/537.36',
    }

    def __init__(self, uuid: str, login_token: str = None) -> None:
        self._uuid: str = uuid
        self._login_token: str = login_token

    @classmethod
    def _gen_websocket_addr(cls) -> str:
        server: int = random.randint(1, 999)
        suffix: str = utils.gen_rand_str(8)

        return f'{cls._ws_base_url}/{server}/{suffix}/websocket'

    @classmethod
    def _new_websocket_connection(cls) -> WebSocket:
        ws = WebSocket()

        ws.connect(cls._gen_websocket_addr(), header=cls._headers)

        # First skip is letter `o`
        ws.recv()
        # Second skip is server id
        ws.recv()

        cls._send_json_object(ws, {
            'msg': 'connect',
            'version': '1',
            'support': ['1', 'pre2', 'pre1']
        })

        assert cls._parse_json_response(ws.recv()).get('msg') == 'connected'

        return ws

    @classmethod
    def _send_json_object(cls, ws: WebSocket, data: dict) -> None:
        raw_data: str = json.dumps([json.dumps(data)])
        ws.send(raw_data)

    @classmethod
    def _parse_json_response(cls, data: str) -> dict:
        raw_response = json.loads(data[1:])
        return json.loads(raw_response[0])

    @classmethod
    def _subscribe(cls, ws: WebSocket, name: str, params: list) -> list[dict]:
        sub_id = utils.gen_rand_str(17)

        cls._send_json_object(ws, {
            'msg': 'sub',
            'id': sub_id,
            'name': name,
            'params': params,
        })

        result = []

        while (response := cls._parse_json_response(ws.recv())).get('subs') != [sub_id]:
            result.append(response)

        cls._send_json_object(ws, {
            'msg': 'unsub',
            'id': sub_id,
        })

        while (response := cls._parse_json_response(ws.recv())).get('msg') != 'nosub':
            pass

        return result

    def __getstate__(self):
        state = self.__dict__.copy()

        state.pop('_ws', None)

        return state

    def _get_task_id(self) -> str:
        response = self._subscribe(self._ws, 'taskexists', [self.uuid])

        return response[0]['fields']['taskObjectId']['$value']

    def _get_processes(self) -> list[dict]:
        return self._subscribe(self._ws, 'process', [
            {
                'taskID': {
                    '$type': 'oid',
                    '$value': self.id,
                },
                'status': 100,
                'important': True,
            }
        ])

    def _get_sample_uuid(self) -> str:
        response = self._subscribe(self._ws, 'singleTask',
            [{'$type': 'oid', '$value': self.id}, False])

        return response[0]['fields']['public']['objects']['mainObject']['uuid']

    def _get_exec_time(self) -> int:
        response = self._subscribe(self._ws, 'singleTask',
            [{'$type': 'oid', '$value': self.id}, False])

        times = response[0]['fields']['times']

        return (times['stopExec']['$date'] - times['startExec']['$date']) // 1000

    def _get_sample_bytes(self) -> bytes:
        response = requests.get(self.sample_url,
            headers=self._headers, stream=True,
            cookies={'tokenLogin': self._login_token})

        zip_file = ZipFile(BytesIO(response.content), 'r')

        fileinfo = zip_file.infolist()[0]

        return zip_file.read(fileinfo, self._default_zip_password)

    def _get_connections_num(self) -> int:
        response = self._subscribe(self._ws, 'ipsCounter', [
            {
                '$type': 'oid',
                '$value': self.id,
            },
            False
        ])

        return response[0]['fields']['count']

    def _get_connections(self) -> list[dict]:
        response = self._subscribe(self._ws, 'ips', [
            {
                'taskId': {
                    '$type': 'oid',
                    '$value': self.id,
                },
                'searchParam': None,
            },
            self.connections_num
        ])

        return [
            {
                'ip': item['fields']['ip'],
                'port': item['fields']['port'],
                'send': item['fields']['traffic']['send'],
                'recv': item['fields']['traffic']['recv'],
                'domain': item['fields'].get('domain', None),
            }
            for item in response
        ]

    @cached_property
    def _ws(self) -> WebSocket:
        return self._new_websocket_connection()

    @property
    def uuid(self) -> str:
        return self._uuid

    @cached_property
    def id(self) -> str:
        return self._get_task_id()

    @cached_property
    def processes(self) -> list[dict]:
        return self._get_processes()

    @cached_property
    def touched_files_num(self) -> int:
        return sum(x['fields']['events_counters']['dropped_files']
                   for x in self.processes)

    @cached_property
    def sample_uuid(self) -> str:
        return self._get_sample_uuid()

    @cached_property
    def sample_url(self) -> str:
        return self._content_base_url.format(
            task_uuid=self.uuid, object_id=self.sample_uuid)

    @cached_property
    def sample_bytes(self) -> str:
        if self._login_token is None:
            raise PermissionError('You need to provide login token to get the sample')

        return self._get_sample_bytes()

    @cached_property
    def execution_time(self) -> int:
        return self._get_exec_time()

    @cached_property
    def connections_num(self) -> int:
        return self._get_connections_num()

    @cached_property
    def connections(self) -> list[dict]:
        return self._get_connections()

    @cached_property
    def ips(self) -> list[str]:
        return [item['ip'] for item in self.connections]

    @cached_property
    def domains(self) -> list[str]:
        return list(set(
            item['domain'] for item in self.connections
            if item['domain'] is not None
        ))

    @cached_property
    def traffic_send(self) -> int:
        return sum(item['send'] for item in self.connections)

    @cached_property
    def traffic_recv(self) -> int:
        return sum(item['recv'] for item in self.connections)

class CachedAnyRunTask:
    _database_path: str = '_cache/samples'

    def __init__(self, uuid: str, login_token: str = None):
        self._db: shelve.Shelf = None
        self._task: AnyRunTask = AnyRunTask(uuid, login_token)

    @property
    def uuid(self) -> str:
        return self._task.uuid

    def __enter__(self) -> AnyRunTask:
        self._db = shelve.open(self._database_path)

        if self.uuid in self._db:
            self._task = self._db[self.uuid]

        return self._task

    def __exit__(self, exc_type, exc_value, traceback) -> None:
        self._db[self.uuid] = self._task
        self._db.close()
