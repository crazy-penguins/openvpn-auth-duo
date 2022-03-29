import logging
from datetime import timedelta
from typing import Dict

from cacheout import CacheManager
from prometheus_client import Counter
from duo_client.auth import Auth
from ._version import __version__
from .openvpn import ManagementInterface
from .util import errors
from .util.thread_pool import ThreadPoolExecutorStackTraced
from .base_authenticator import BaseAuthenticator
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


class DuoAuthenticator(BaseAuthenticator):
    def __init__(
        self,
        ikey: str,
        skey: str,
        api_host: str,
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
        super().__init__(
            mysql_host, mysql_username, mysql_password, mysql_database,
            threads, host, port, unix_socket, password
        )
        self.ikey = ikey
        self.skey = skey
        self.api_host = api_host
        self.auth = Auth(ikey, skey, api_host)

    def is_trusted(self, client):
        env = client['env']
        username = env['common_name']
        untrusted_ip = env['untrusted_ip']
        data = self.query(
            'select token from trusted_device_token '
            'where ip_address=%s and username=%s',
            [untrusted_ip, username])
        token = data[0]['token'] if data else None
        result = self.auth.preauth(
            username=username,
            ipaddr=untrusted_ip,
            trusted_device_token=token)
        return result


    def save_device_token(self, client, token):
        if not token:
            return
        env = client['env']
        username = env['common_name']
        untrusted_ip = env['untrusted_ip']
        data = self.query(
            'select token from trusted_device_token '
            'where ip_address=%s and username=%s',
            [untrusted_ip, username])
        if data:
            self.query(
                'update trusted_device_token'
                ' set token=%s'
                ' where ip_address=%s and username=%s',
                [token, untrusted_ip, username])
        else:
            self.query(
                'insert into trusted_device_token (token, ip_address, username)'
                ' values (%s, %s, %s)'
                [token, untrusted_ip, username])


    def authenticate_client(self, client: Dict):
        username = client['env']['common_name']
        log.info('username: %s', username)
        duo = self.is_trusted(client)
        if not duo.get('result') == 'allow':
            duo = self.auth.auth('push', username, device='auto')
            log.info('[duo] %s', duo)
            if duo.get('result') == 'allow':
                self.save_device_token(client, duo.get('trusted_device_token'))
        if duo.get('result') == 'allow':
            self.vpn_command(f"client-auth-nt {client['cid']} {client['kid']}")
        else:
            self.vpn_command(
                f'client-deny {client["cid"]} {client["kid"]} "no_response" '
                '"we did not receive a response from duo"'
            )
