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
from .base_authenticator import BaseAuthenticator


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


class TotpAuthenticator(BaseAuthenticator):
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
        super().__init__(
            mysql_host, mysql_username, mysql_password, mysql_database,
            threads, host, port, unix_socket, password)
        self.ldap_enabled = ldap_enabled
        self.ldap_search_base = ldap_search_base
        self.ldap_servers = ldap_servers
        self.token_expiration = token_expiration

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
