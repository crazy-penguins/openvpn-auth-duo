from datetime import datetime, timedelta
import logging
from base64 import b64encode, b64decode
from typing import Dict
from hashlib import sha256
from cacheout import CacheManager
import pytz
from prometheus_client import Counter
from duo_client.auth import Auth
from pyotp import TOTP
from mysql.connector import connect
from mysql.connector import Error as MysqlError
from mysql.connector.errors import OperationalError
from ._version import __version__
from .openvpn import ManagementInterface
from .util import errors, b64encode_string, generated_id
from .util.thread_pool import ThreadPoolExecutorStackTraced




log = logging.getLogger(__name__)


class BaseAuthenticator:
    def __init__(
        self,
        mysql_host: str,
        mysql_username: str,
        mysql_password: str,
        mysql_database: str,
        threads: int,
        host: str = None,
        port: int = None,
        unix_socket: str = None,
        password: str = None,
    ):
        self.mysql_host = mysql_host
        self.mysql_username = mysql_username
        self.mysql_password = mysql_password
        self.mysql_pool_name = 'openvpn_auth_duo'
        self.mysql_pool_size = threads
        self.mysql_database = mysql_database
        if (host and port) or unix_socket:
            self._openvpn = ManagementInterface(host, port, unix_socket, password)
            self._openvpn.connect()
        self._thread_pool = ThreadPoolExecutorStackTraced(max_workers=threads)

    def run(self) -> None:
        log.info('Running openvpn-auth-duo %s', __version__)
        try:
            while True:
                message = self._openvpn.receive()
                if not message:
                    log.error('Connection to OpenVPN closed. Reconnecting...')
                    self._openvpn.connect(True)
                    continue

                if message.startswith('ERROR:'):
                    log.error(message)
                    continue

                if message.startswith('>CLIENT:DISCONNECT'):
                    self._thread_pool.submit(self.client_disconnect, message)

                elif message.startswith('>CLIENT:CONNECT'):
                    self._thread_pool.submit(self.client_connect, message)

                elif message.startswith('>CLIENT:REAUTH'):
                    self._thread_pool.submit(self.client_reauth, message)

                self._states['challenge'].delete_expired()
                self._states['auth_token'].delete_expired()
        except KeyboardInterrupt:
            pass
        except Exception as e:
            log.exception('exception in main thread: %s', e)

    def mysql_connection(self):
        return connect(
            pool_name=self.mysql_pool_name,
            pool_size=self.mysql_pool_size,
            pool_reset_session=False,
            user=self.mysql_username,
            password=self.mysql_password,
            host=self.mysql_host,
            database=self.mysql_database,
            autocommit=True,
            time_zone='+00:00',
        )

    def query(self, sql, params=None):
        try:
            with self.mysql_connection() as conn:
                with conn.cursor() as cursor:
                    cursor.execute(sql, params)
                    data = []
                    if cursor.description:
                        header = [ x[0].lower().strip() for x in cursor.description ]
                        for x in cursor.fetchall():
                            data.append(dict(zip(header, x)))
                    return data
        except OperationalError as ex:
            log.exception('exception in main thread: %s', ex)
            log.exception('ex.errno: %s', ex.errno)
            log.exception('ex.msg: %s', ex.msg)
        except Exception as ex:
            log.info('error: %s.%s', ex.__module__, ex.__class__.__name__)
            log.info('error: %s', ex)

    @classmethod
    def parse_client_data(cls, data: str) -> dict:
        client = {
            'env': {},
            'reason': None,
            'cid': None,
            'kid': None,
            'state_id': None,
        }

        for line in data.splitlines():
            try:
                if line.startswith('>CLIENT:CONNECT') or line.startswith(
                    '>CLIENT:REAUTH'
                ):
                    client_info = line.split(',')
                    client['reason'] = client_info[0].replace('>CLIENT:', '').lower()
                    client['cid'] = client_info[1]
                    client['kid'] = client_info[2]
                elif line.startswith('>CLIENT:DISCONNECT'):
                    client_info = line.split(',')
                    client['reason'] = client_info[0].replace('>CLIENT:', '').lower()
                    client['cid'] = client_info[1]
                elif line.startswith('>CLIENT:ENV,'):
                    env_line = line.split(',', 1)[-1]
                    if env_line != 'END':
                        if '=' in env_line:
                            pieces = env_line.split('=', 1)
                            client['env'][pieces[0].lower()] = pieces[1]
                        else:
                            client['env'][env_line] = ''
                else:
                    raise errors.ParseError(f"Can't parse line: {line}")
            except Exception:
                raise errors.ParseError(f"Can't parse line: {line}")

        return client

    def vpn_command(self, message):
        self._openvpn.send_command(message)

    @classmethod
    def decode_password(cls, client):
        env = client['env']
        password = env['password']
        decode = False
        if password.startswith('CRV1'):
            password = password.split('::')[-1]
        elif password.startswith('SCRV1'):
            password = password.split(':')[1]
            decode = True
        if decode:
            password = password.encode('utf-8')
            password = b64decode(password).decode('utf-8')
        return password

    @classmethod
    def lowercase_dict(cls, data):
        return { key.lower(): value for key, value in data.items() }

    def authenticate_client(self, client):
        pass

    def send_client_challenge(self, client: dict, challenge):
        username = client['env']['username']
        username_b64 = b64encode_string(username)
        state_id = generated_id()
        challenge = f'CRV1:E,R:{state_id}:{username_b64}:{challenge}'
        self.vpn_command(
            f'client-deny {client["cid"]} {client["kid"]} '
            f'"client_challenge" "{challenge}"')

    def client_connect(self, data: str) -> None:
        client = self.parse_client_data(data)
        log.info('[%s] Received client connect', client['cid'])
        log.info('[%s] Received client connect', client['env']['common_name'])
        self.authenticate_client(client)

    def client_disconnect(self, data: str) -> None:
        client = self.parse_client_data(data)
        log.info('[%s] Received client disconnect event', client['cid'])

    def client_reauth(self, data: str) -> None:
        client = self.parse_client_data(data)
        log.info('[%s] Received client reauth event', client['cid'])
        self.authenticate_client(client)

