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


openvpn_totp_events = Counter(
    "openvpn_totp_events", "track events", ["event"]
)
openvpn_totp_auth_total = Counter(
    "openvpn_totp_auth_total", "auth total", ["flow"]
)
openvpn_totp_auth_succeeded = Counter(
    "openvpn_totp_auth_succeeded", "auth succeeded", ["flow"]
)
openvpn_totp_auth_failures = Counter(
    "openvpn_totp_auth_failures", "auth failures", ["flow"]
)


log = logging.getLogger(__name__)


class TotpAuthenticator(object):
    def __init__(
        self,
        mysql_host: str,
        mysql_username: str,
        mysql_password: str,
        mysql_database: str,
        threads: int,
        ldap_enabled: bool = False,
        ldap_search_base: str = None,
        ldap_servers: str = None,
        host: str = None,
        port: int = None,
        unix_socket: str = None,
        password: str = None,
        token_expiration = 15,
    ):
        self.mysql_host = mysql_host
        self.mysql_username = mysql_username
        self.mysql_password = mysql_password
        self.mysql_pool_name = 'totp_authenticator'
        self.mysql_pool_size = threads
        self.mysql_database = mysql_database
        self.ldap_enabled = ldap_enabled
        self.ldap_search_base = ldap_search_base
        self.ldap_servers = ldap_servers
        self.token_expiration = token_expiration
        if (host and port) or unix_socket:
            self._openvpn = ManagementInterface(host, port, unix_socket, password)
            self._openvpn.connect()
        self._states = CacheManager({
            'challenge': {'maxsize': 256, 'ttl': 600},
            'authenticated': {'maxsize': 256, 'ttl': 0},
            'auth_token': {'maxsize': 256, 'ttl': 86400},
        })
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

    def last_login(self, username, ip):
        results = self.query(
            'select last_sign_in from last_sign_in where email=%s and ip_address=%s'
            ' order by last_sign_in desc',
            [ username, ip ])
        if results:
            result = results[0]
            return result['last_sign_in'].replace(tzinfo=pytz.utc)
        return None

    def authenticated(self, client, last):
        env = client['env']
        username = env['common_name']
        untrusted_ip = env['untrusted_ip']
        self.vpn_command(f"client-auth-nt {client['cid']} {client['kid']}")
        self.save_last_login(username, untrusted_ip, last)

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

    def connect_to_ldap(self, upn, password, ldap_servers=None):
        from ldap3 import ServerPool as LdapServerPool
        from ldap3 import Connection as LdapConnection
        from ldap3 import ROUND_ROBIN
        ldap_servers = ldap_servers or self.ldap_servers
        log.debug('[ldap] servers: %s', ldap_servers)
        ldap_servers = ldap_servers.split(',')
        ldap_servers = [ x.strip() for x in ldap_servers ]
        pool = LdapServerPool(ldap_servers, ROUND_ROBIN)
        ldap_connection = LdapConnection(pool, upn, password)
        return ldap_connection

    @classmethod
    def lowercase_dict(cls, data):
        return { key.lower(): value for key, value in data.items() }

    def authenticate_via_ldap(self, client):
        from ldap3 import ALL_ATTRIBUTES
        if not self.ldap_enabled:
            return True, [], None
        env = client['env']
        upn = env['common_name']
        password = self.decode_password(client)
        ldap_servers, ldap_search_base = self.get_ldap_settings(client)
        ldap_connection = self.connect_to_ldap(upn, password, ldap_servers)
        if not ldap_connection.bind():
            log.info('authentication via ldap failed')
            return False, [], None
        log.debug('[ldap] base: %s', self.ldap_search_base)
        ldap_connection.search(
            ldap_search_base or self.ldap_search_base,
            '(&'
            f'(userprincipalname={upn})'
            '(objectClass=user)'
            '(!(userAccountControl:1.2.840.113556.1.4.803:=2)))',
            attributes=ALL_ATTRIBUTES)
        response = ldap_connection.response
        ldap_connection.unbind()
        if not response:
            return False, [], None
        response = response[0]
        attrs = self.lowercase_dict(response['attributes'])
        log.info('authentication via ldap successful')
        return True, attrs.get('memberof') or [], attrs.get('openvpn_totp')

    def query_secret_key(self, username):
        results = self.query(
            'select * from totp where email=%s',
            [ username ])
        log.info('[results] found %s results', len(results))
        if not results:
            log.info('username not found in totp table, denying login')
            return None
        return results[0]['secret_key']

    def authenticate_client(self, client: Dict):
        env = client['env']
        username = env['common_name']
        password = env['password']
        log.info('username: %s', username)
        log.debug('password: %s', password)
        # for key, value in env.items():
        #     log.debug('[env] %s => %s', key, value)
        untrusted_ip = env['untrusted_ip']
        last = self.last_login(username, untrusted_ip)
        delta = timedelta(days=self.token_expiration)
        secret_key = None
        if last and datetime.now(tz=pytz.utc) - last <= delta:
            # if a user has signed in from this ip within the last 15 days
            # don't request another otp code
            self.vpn_command(f"client-auth-nt {client['cid']} {client['kid']}")
            return

        if self.ldap_enabled:
            result, groups, secret_key = self.authenticate_via_ldap(client)
            if not result:
                self.vpn_command(
                    f'client-deny {client["cid"]} {client["kid"]} "bad_response" '
                    '"incorrect username or password"'
                )

        crv1 = password.startswith('CRV1') or password.startswith('SCRV1')
        totp_in_password = len(password) == 6 and password.isdigit()
        log.info('crv1: %s', crv1)
        log.info('totp_in_password: %s', totp_in_password)
        if crv1 or totp_in_password:
            secret_key = secret_key or self.query_secret_key(username)
            if not secret_key:
                self.vpn_command(
                    f'client-deny {client["cid"]} {client["kid"]} "no_response" '
                    '"user not authorized for logon"'
                )
                return
            otp = TOTP(secret_key)
            pieces = password.split(':')
            totp_response = pieces[-1]
            log.info('response: %s', totp_response)
            if pieces[0] == 'SCRV1':
                response_bytes = totp_response.encode('utf-8')
                totp_response = b64decode(response_bytes).decode('utf-8')
                log.info('response: %s', totp_response)
            if otp.verify(totp_response):
                self.authenticated(client, last)
            else:
                self.vpn_command(
                    f'client-deny {client["cid"]} {client["kid"]} "bad_response" '
                    '"incorrect otp"'
                )
            return
        self.send_client_challenge(client, 'Please enter your one-time code')

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
        openvpn_totp_events.labels('connect').inc()
        self.authenticate_client(client)

    def client_disconnect(self, data: str) -> None:
        client = self.parse_client_data(data)
        log.info('[%s] Received client disconnect event', client['cid'])
        openvpn_totp_events.labels('disconnect').inc()

    def client_reauth(self, data: str) -> None:
        client = self.parse_client_data(data)
        log.info('[%s] Received client reauth event', client['cid'])
        openvpn_totp_events.labels('reauth').inc()
        self.authenticate_client(client)

    def save_last_login(self, username, ip, last):
        if last:
            self.query(
                'update last_sign_in'
                ' set last_sign_in=current_timestamp'
                ' where '
                '   email=%s'
                '   and ip_address=%s', [username, ip, ]
            )
        else:
            self.query(
                'insert into last_sign_in (email, ip_address)'
                ' values (%s, %s)', [username, ip, ]
            )

    def register_ldap_domain(self, ldap_domain):
        log.info('[ldap] registering %s', ldap_domain)
        sql = 'select domain from ldap_settings where domain=%s'
        domains = self.query(sql, [ ldap_domain ])
        params = [ self.ldap_servers, self.ldap_search_base, ldap_domain ]
        if domains:
            log.info('[ldap] updating entries for %s', ldap_domain)
            sql = """
            update ldap_settings set servers=%s, search_base=%s
            where domain=%s
            """
        else:
            log.info('[ldap] inserting new entry for %s', ldap_domain)
            sql = """
            insert into ldap_settings (servers, search_base, domain) values (
              %s, %s, %s
            )
            """
        self.query(sql, params)

    def get_ldap_settings(self, client):
        env = client['env']
        upn = env['common_name']
        domain = upn.split('@')[-1]
        if not upn:
            return None, None
        sql = 'select servers, search_base from ldap_settings where domain=%s'
        domains = self.query(sql, [ domain ])
        domains = domains or self.query(sql, [ 'default' ]) or []
        for x in domains:
            return x['servers'], x['search_base']
        return None, None
