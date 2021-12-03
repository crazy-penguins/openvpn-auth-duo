import logging
from typing import Dict

from cacheout import CacheManager
from prometheus_client import Counter
from duo_client.auth import Auth
from ._version import __version__
from .openvpn import ManagementInterface
from .util import errors
from .util.thread_pool import ThreadPoolExecutorStackTraced

openvpn_duo_events = Counter(
    "openvpn_duo_events", "track events", ["event"]
)
openvpn_duo_auth_total = Counter(
    "openvpn_duo_auth_total", "auth total", ["flow"]
)
openvpn_duo_auth_succeeded = Counter(
    "openvpn_duo_auth_succeeded", "auth succeeded", ["flow"]
)
openvpn_auth_azure_ad_auth_failures = Counter(
    "openvpn_duo_auth_failures", "auth failures", ["flow"]
)


log = logging.getLogger(__name__)


class DuoAuthenticator(object):
    def __init__(
        self,
        ikey: str,
        skey: str,
        api_host: str,
        threads: int,
        host: str = None,
        port: int = None,
        unix_socket: str = None,
        password: str = None,
    ):
        self.ikey = ikey
        self.skey = skey
        self.api_host = api_host
        self.auth = Auth(ikey, skey, api_host)
        self._openvpn = ManagementInterface(host, port, unix_socket, password)
        self._openvpn.connect()
        self._states = CacheManager(
            {
                'challenge': {'maxsize': 256, 'ttl': 600},
                'authenticated': {'maxsize': 256, 'ttl': 0},
                'auth_token': {'maxsize': 256, 'ttl': 86400},
            }
        )
        self._thread_pool = ThreadPoolExecutorStackTraced(max_workers=threads)

    def run(self) -> None:
        log.info("Running openvpn-auth-duo %s" % __version__)
        try:
            while True:
                message = self._openvpn.receive()
                if not message:
                    log.error("Connection to OpenVPN closed. Reconnecting...")
                    self._openvpn.connect(True)
                    continue

                if message.startswith("ERROR:"):
                    log.error(message)
                    continue

                if message.startswith(">CLIENT:DISCONNECT"):
                    self._thread_pool.submit(self.client_disconnect, message)

                elif message.startswith(">CLIENT:CONNECT"):
                    self._thread_pool.submit(self.client_connect, message)

                elif message.startswith(">CLIENT:REAUTH"):
                    self._thread_pool.submit(self.client_reauth, message)

                self._states["challenge"].delete_expired()
                self._states["auth_token"].delete_expired()
        except KeyboardInterrupt:
            pass
        except Exception as e:
            log.exception('exception in main thread: %s', e)

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
                    client_env = line.split(',')[1].split('=')
                    client['env'][client_env[0]] = (
                        client_env[1] if len(client_env) == 2 else ''
                    )
                else:
                    raise errors.ParseError(f"Can't parse line: {line}")
            except Exception:
                raise errors.ParseError(f"Can't parse line: {line}")

        return client

    def vpn_command(self, message):
        self._openvpn.send_command(message)

    def authenticate_client(self, client: Dict):
        username = client['env']['common_name']
        log.info('username: %s', username)
        duo = self.auth.auth('push', username, device='auto')
        log.info('[duo] %s', duo)
        if duo.get('status') == 'allow':
            self.vpn_command(f"client-auth-nt {client['cid']} {client['kid']}")
        else:
            self.vpn_command(
                f'client-deny {client["cid"]} {client["kid"]} "no_response" '
                '"we did not receive a response from duo"'
            )

    def client_connect(self, data: str) -> None:
        client = self.parse_client_data(data)
        log.info('[%s] Received client connect', client['cid'])
        log.info('[%s] Received client connect', client['env']['common_name'])
        openvpn_duo_events.labels('connect').inc()
        self.authenticate_client(client)

    def client_disconnect(self, data: str) -> None:
        client = self.parse_client_data(data)
        log.info('[%s] Received client disconnect event', client['cid'])
        openvpn_duo_events.labels('disconnect').inc()

    def client_reauth(self, data: str) -> None:
        client = self.parse_client_data(data)
        log.info('[%s] Received client reauth event', client['cid'])
        openvpn_duo_events.labels('reauth').inc()
        self.vpn_command(f"client-auth-nt {client['cid']} {client['kid']}")
