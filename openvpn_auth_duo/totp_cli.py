import io
import logging
from socket import gethostname

import configargparse
from concurrent_log_handler.queue import setup_logging_queues
from prometheus_client import Info, start_http_server
from pyotp import random_base32
from pyotp import TOTP
from qrcode import QRCode
from ._version import __version__
from .totp_authenticator import TotpAuthenticator


def qr_code(st):
    qr = QRCode()
    qr.add_data(st)
    f = io.StringIO()
    qr.print_ascii(out=f)
    f.seek(0)
    print(f.read())


def main():
    log = logging.getLogger(__name__)
    parser = configargparse.ArgParser(
        default_config_files=[
            '/etc/openvpn-auth-duo/config.conf',
            '~/.openvpn-auth-duo',
        ]
    )

    parser.add_argument(
        '-c',
        '--config',
        is_config_file=True,
        help='path of config file',
        env_var='AAD_CONFIG_PATH',
    )
    parser.add_argument(
        '-V',
        '--version',
        action='version',
        version='%(prog)s {version}'.format(version=__version__),
    )
    parser.add_argument(
        '-t',
        '--threads',
        default=10,
        env_var='AAD_THREAD_COUNT',
        help='Amount of threads to handle authentication',
        type=int,
    )

    parser_duo = parser.add_argument_group('commands')
    parser_duo.add_argument(
        '--enroll',
        help='switch which, if specified, enrolls a user for totp',
        default=False,
        action='store_true',
    )
    parser_duo.add_argument(
        '--reenroll',
        help='switch which, if specified, reenrolls a user for totp and '
             'generates a new totp secret key',
        default=False,
        action='store_true',
    )
    parser_duo.add_argument(
        '--email',
        help='the email address of the person to enroll',
    )
    parser_duo.add_argument(
        '--migrate',
        help='migrates the schema to the latest version',
        default=False,
        action='store_true',
    )

    parser_duo = parser.add_argument_group('mysql')
    parser_duo.add_argument(
        '--mysql-host',
        help='mysql host',
        env_var='OVAD_MYSQL_HOST',
        default='127.0.0.1',
    )
    parser_duo.add_argument(
        '--mysql-username',
        help='username used to login to the mysql host',
        env_var='OVAD_MYSQL_USERNAME',
    )
    parser_duo.add_argument(
        '--mysql-password',
        help='password to login to mysql ',
        env_var='OVAD_MYSQL_PASSWORD',
        default='',
    )
    parser_duo.add_argument(
        '--mysql-database',
        default='totp',
        help='database housing the totp schema',
        env_var='OVAD_MYSQL_DATABASE',
    )

    parser_authentication = parser.add_argument_group('OpenVPN User Authentication')
    parser_authentication.add_argument(
        '--auth-token',
        action='store_true',
        help='Use auth token to re-authenticate clients',
        env_var='AAD_AUTH_TOKEN',
    )
    parser_authentication.add_argument(
        '--token-expiration',
        type=int,
        default=15,
        help='the number of days a user can sign in without the TOTP after '
             'a successful login with totp',
        env_var='TOTP_TOKEN_EXPIRATION',
    )
    parser_authentication.add_argument(
        '--remember-user',
        action='store_true',
        help='If user authenticated once, the users refresh token is '
             'used to reauthenticate silently if possible.',
        env_var='AAD_REMEMBER_USER',
    )
    parser_authentication.add_argument(
        '--verify-common-name',
        action='store_true',
        help='Check if common_name matches Azure AD UPN',
        env_var='AAD_VERIFY_COMMON_NAME',
    )

    ldap_options = parser.add_argument_group('ldap settings')
    ldap_options.add_argument(
        '--ldap-enabled',
        help='indicates whether to authenticate the username / password with ldap.',
        env_var='OVAD_LDAP_ENABLED',
        action='store_true',
    )
    ldap_options.add_argument(
        '--ldap-servers',
        help='the ldap servers to try for authentication',
        env_var='OVAD_LDAP_SERVERS',
    )
    ldap_options.add_argument(
        '--ldap-search-base',
        help='the ldap search base e.g. "DC=contoso,DC=com"',
        env_var='OVAD_LDAP_SEARCH_BASE',
    )
    ldap_options.add_argument(
        '--register-ldap-domain',
        help='allows registration of a domain. saves settings in the database',
        action='store_true',
    )
    ldap_options.add_argument(
        '--ldap-domain',
        help='the ldap domain you want to register'
    )

    parser_openvpn = parser.add_argument_group('OpenVPN Management Interface settings')
    parser_openvpn.add_argument(
        '-H',
        '--ovpn-host',
        help='Host of OpenVPN management interface.',
        env_var='AAD_OVPN_HOST',
    )
    parser_openvpn.add_argument(
        '-P',
        '--ovpn-port',
        help='Port of OpenVPN management interface.',
        env_var='AAD_OVPN_PORT',
        type=int,
    )
    parser_openvpn.add_argument(
        '-s',
        '--ovpn-socket',
        help='Path of socket or OpenVPN management interface.',
        env_var='AAD_OVPN_SOCKET_PATH',
    )
    parser_openvpn.add_argument(
        '-p',
        '--ovpn-password',
        help='Password for OpenVPN management interface.',
        env_var='AAD_OVPN_PASSWORD',
    )

    parser_prometheus = parser.add_argument_group('Prometheus settings')
    parser_prometheus.add_argument(
        '--prometheus',
        action='store_true',
        env_var='AAD_PROMETHEUS_ENABLED',
        help='Enable prometheus statistics',
    )
    parser_prometheus.add_argument(
        '--prometheus-listen-addr',
        env_var='AAD_PROMETHEUS_LISTEN_HOST',
        default='',
        help='prometheus listen addr',
    )
    parser_prometheus.add_argument(
        '--prometheus-listen-port',
        type=int,
        env_var='AAD_PROMETHEUS_PORT',
        help=' prometheus statistics',
        default=9723,
    )
    parser_prometheus.add_argument(
        '--log-level',
        default=logging.INFO,
        type=lambda x: getattr(logging, x),
        env_var='AAD_LOG_LEVEL',
        help='Configure the logging level.',
    )

    options = parser.parse_args()

    # convert all configured loggers to use a background thread
    setup_logging_queues()

    logging.basicConfig(
        level=options.log_level, format='%(asctime)s %(levelname)s %(message)s'
    )

    if options.prometheus:
        start_http_server(
            options.prometheus_listen_port, options.prometheus_listen_addr
        )
        i = Info('openvpn_auth_azure_ad_version', 'info of openvpn-auth-azure-ad')
        i.info({'version': __version__})

    authenticator = TotpAuthenticator(
        mysql_host=options.mysql_host,
        mysql_username=options.mysql_username,
        mysql_password=options.mysql_password,
        mysql_database=options.mysql_database,
        threads=options.threads,
        ldap_enabled=options.ldap_enabled,
        ldap_servers=options.ldap_servers,
        ldap_search_base=options.ldap_search_base,
        host=options.ovpn_host,
        port=options.ovpn_port,
        unix_socket=options.ovpn_socket,
        password=options.ovpn_password,
    )
    if options.migrate:
        from pkg_resources import resource_string
        sql = resource_string('openvpn_auth_duo', 'schema.sql')
        sql = sql.decode('utf-8')
        authenticator.query(sql)
    elif options.enroll:
        email = options.email
        existing = authenticator.query(
            'select * from totp where email=%s',
            [email])
        if existing:
            secret_key = existing[0]['secret_key']
        else:
            secret_key = random_base32()
            authenticator.query(
                'insert into totp (email, secret_key)'
                ' values (%s, %s)', [email, secret_key])
        print(secret_key)
        totp = TOTP(secret_key)
        hostname = gethostname()
        uri = totp.provisioning_uri(
            name=email,
            issuer_name=f'openvpn {hostname}',
        )
        print(uri)
        qr_code(uri)
    elif options.reenroll:
        email = options.email
        existing = authenticator.query(
            'select * from totp where email=%s',
            [email])
        if existing:
            log.info('[enroll] %s exists', email)
            secret_key = random_base32()
            authenticator.query(
                'update totp set secret_key = %s'
                ' where email=%s', [secret_key, email])
            print(secret_key)
            totp = TOTP(secret_key)
            hostname = gethostname()
            uri = totp.provisioning_uri(
                name=email,
                issuer_name=f'openvpn {hostname}',
            )
            print(uri)
            qr_code(uri)
        else:
            log.info('[enroll] %s does not exist', email)
    elif options.register_ldap_domain:
        authenticator.register_ldap_domain(options.ldap_domain)
    else:
        authenticator.run()
