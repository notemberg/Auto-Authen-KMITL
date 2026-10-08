import uuid
import argparse  
import json
import shutil
import getpass
import signal
import time
import requests
import sys
import os

username = ''
password = ''
ipAddress= ''
acip="10.252.13.10"
umac = ''.join(['{:02x}'.format((uuid.getnode() >> ele) & 0xff) for ele in range(0,8*6,8)][::-1])
time_repeat = 5*60 
max_login_attempt = 20

client_ip = ''
server_url = 'https://portal.kmitl.ac.th:19008/portalauth/login'
server_url_logout = 'https://portal.kmitl.ac.th:19008/portalauth/logout'
server_url_heartbeat = 'https://nani.csc.kmitl.ac.th/network-api/data/'
data = ''
agent = requests.session()

# what login() tells its caller
LOGIN_OK = 'ok'
LOGIN_REJECTED = 'rejected'
LOGIN_UNREACHABLE = 'unreachable'

client_token = ''
logged_in = False

request_timeout = 10         # so a hung portal cannot block the script forever
retry_delay = 10             # wait between failed login attempts
session_lifetime = 8*60*60   # the portal drops the session after 8 hours
reset_margin = 10*60         # renew the session this long before it expires


# handle Ctrl+C and kill
def signal_handler(signal, frame):
    if logged_in:
        print_format('Logging out before exit...', end='\n')
        logout()
    print_format('Good bye!', end='\n')
    sys.exit(0)


signal.signal(signal.SIGINT, signal_handler)
signal.signal(signal.SIGTERM, signal_handler)


# determine terminal size
large_terminal = True
column, line = shutil.get_terminal_size()
if column < 108:
    large_terminal = False


# arguments parser
parser = argparse.ArgumentParser(
    description='Automatically authenticate into KMITL network system.')
parser.add_argument('-u', '--username', dest='username',
                    help='username without @kmitl.ac.th (usually student ID)')
parser.add_argument('-p', '--password', dest='password', help='password')
parser.add_argument('-ip', '--IpAddress', dest='ipAddress', help='ipAddress')
parser.add_argument('-i', '--interval', dest='interval', type=int,
                    help='heartbeat interval in second (default: {} seconds)'.format(time_repeat))
parser.add_argument('--max-login-attempt', dest='max_attempt', type=int,
                    help='maximum login attempt (default: {} times)'.format(max_login_attempt))
parser.add_argument('--config', dest='config', action='store_const',
                    const=True, default=False, help='create config file')

def print_format(*args, large_only=False, small_only=False, show_time=True, end='\n\n', **kwargs):
    if (large_only and not large_terminal) or (small_only and large_terminal):
        return

    if large_terminal:
        print('\t', end='')
    if show_time:
        print(time.asctime(time.localtime()), '[x]', end=' ')
    print(*args, **kwargs, end=end)


def print_error(*args, **kwargs):
    print_format(*args, **kwargs, end='\n')
    #sys.exit(1)


def init():
    logo = '''
         ██████╗███████╗    ██╗  ██╗ ██████╗ ██╗   ██╗███████╗███████╗
        ██╔════╝██╔════╝    ██║  ██║██╔═══██╗██║   ██║██╔════╝██╔════╝
        ██║     █████╗      ███████║██║   ██║██║   ██║███████╗█████╗  
        ██║     ██╔══╝      ██╔══██║██║   ██║██║   ██║╚════██║██╔══╝  
        ╚██████╗███████╗    ██║  ██║╚██████╔╝╚██████╔╝███████║███████╗
         ╚═════╝╚══════╝    ╚═╝  ╚═╝ ╚═════╝  ╚═════╝ ╚══════╝╚══════╝
                                                                      
                        https://github.com/CE-HOUSE                   
        
'''

    print_format(logo, large_only=True, show_time=False)
    print_format('CE-HOUSE', show_time=True)

def login():
    """Try to authenticate. Returns LOGIN_OK / LOGIN_REJECTED / LOGIN_UNREACHABLE.

    A rejection is NOT printed here: login() is called from several places, so
    the caller reports it once, together with the attempt count.
    """
    global data, client_token, logged_in
    try:
        content = agent.post(server_url,
                             params={'userName': username, 'userPass': password,
                                     'uaddress': ipAddress, 'umac': umac, 'agreed': 1,
                                     'acip': acip, 'authType': 1},
                             timeout=request_timeout)
    except requests.exceptions.RequestException:
        print_format('Connection lost...', show_time=True, end='\n')
        return LOGIN_UNREACHABLE

    if content.status_code != 200:
        print_format('Error! Portal answered HTTP {}...'.format(content.status_code))
        return LOGIN_UNREACHABLE

    try:
        content_dict = json.loads(content.text)
    except ValueError:
        print_format('Error! Unexpected reply from the portal: {}'.format(content.text[:200]))
        return LOGIN_UNREACHABLE

    if not content_dict.get('success'):
        return LOGIN_REJECTED

    data = content_dict.get('data', {})
    client_token = content_dict.get('token', '')
    logged_in = True
    return LOGIN_OK


def logout():
    """Release the portal session. Safe to call twice; does nothing if not logged in."""
    global client_token, logged_in

    if not logged_in:
        return

    # cleared up-front so a second call (e.g. Ctrl+C during logout) is a no-op
    logged_in = False

    params = {'userName': username, 'uaddress': ipAddress, 'umac': umac,
              'acip': acip, 'authType': 1}
    if client_token:
        params['token'] = client_token

    headers = {
        'Accept': 'application/json, text/javascript, */*; q=0.01',
        'Origin': 'https://portal.kmitl.ac.th:19008',
        'Referer': 'https://portal.kmitl.ac.th:19008/',
        'X-Requested-With': 'XMLHttpRequest',
    }
    if client_token:
        headers['X-XSRF-TOKEN'] = client_token

    client_token = ''

    try:
        content = agent.post(server_url_logout, params=params, headers=headers,
                             data='', timeout=request_timeout)
    except requests.exceptions.RequestException:
        print_format('Logout request failed (network issue)...')
        return

    if content.status_code != 200:
        print_format('Logout failed: HTTP {}'.format(content.status_code))
        return

    try:
        result = json.loads(content.text)
    except ValueError:
        print_format('Logout: unexpected reply from the portal: {}'.format(content.text[:200]))
        return

    if result.get('success'):
        print_format('Logout successful.')
    else:
        print_format('Logout refused by the portal: {}'.format(content.text[:200]))


def heatbeat() -> (bool, bool):
    try:
        content = agent.post(server_url_heartbeat,
                             params={'username': username,
                                     'os': "Chrome v116.0.5845.141 on Windows 10 64-bit",
                                     "speed": 1.29, "newauth": 1},
                             timeout=request_timeout)
    except requests.exceptions.RequestException:
        print_format('Connection lost...')
        time.sleep(1)
        return False, False
    status = content.status_code
    if status == 200:
        print_format('Heartbeat OK...')
        return True, True
    else:
        print_format('Heartbeat failed...')
        return True, False


def checkConnection() -> (bool, bool):
    try:
        content = requests.get('http://detectportal.firefox.com/success.txt',
                               timeout=request_timeout)
    except requests.exceptions.RequestException:
        return False, False
    if content.text == 'success\n':
        return True, True
    return True, False

def start() -> bool:
    """Hold one portal session.

    Returns True when the caller should open a fresh session (the current one is
    about to expire), False when the script should give up (bad credentials).
    """
    rejected_attempt = 0
    printed_logged_in = False
    printed_lost = False
    reset_timer = time.time() + session_lifetime
    login()
    while True:
        if reset_timer - time.time() <= reset_margin:
            # log out first: re-logging in while the old session is still bound
            # to this IP is what the portal rejects
            print_format('Portal session is about to expire, renewing it...')
            logout()
            return True

        connection, internet = checkConnection()
        if connection and internet:
            rejected_attempt = 0
            if not printed_logged_in:  # print only when log in successful
                print('',end='\n')
                print_format('Welcome {}!'.format(username), end='\n')
                print_format('Your IP:', ipAddress, end='\n')
                print_format('Heartbeat every', time_repeat, 'seconds', end='\n')
                print_format('Max login attempt:',max_login_attempt)
                print_format('''
         ██████╗ ██████╗ ███╗   ██╗███╗   ██╗███████╗ ██████╗████████╗███████╗██████╗ 
        ██╔════╝██╔═══██╗████╗  ██║████╗  ██║██╔════╝██╔════╝╚══██╔══╝██╔════╝██╔══██╗
        ██║     ██║   ██║██╔██╗ ██║██╔██╗ ██║█████╗  ██║        ██║   █████╗  ██║  ██║
        ██║     ██║   ██║██║╚██╗██║██║╚██╗██║██╔══╝  ██║        ██║   ██╔══╝  ██║  ██║
        ╚██████╗╚██████╔╝██║ ╚████║██║ ╚████║███████╗╚██████╗   ██║   ███████╗██████╔╝
         ╚═════╝ ╚═════╝ ╚═╝  ╚═══╝╚═╝  ╚═══╝╚══════╝ ╚═════╝   ╚═╝   ╚══════╝╚═════╝ 
''', show_time=False)
                printed_logged_in = True
                printed_lost = False
            time.sleep(time_repeat)
            connection, heatdone = heatbeat()
            if connection and not heatdone:
                if login() == LOGIN_REJECTED:
                    print_format('Portal rejected the re-login after a failed heartbeat.')
            continue

        # No internet. Either the portal dropped us, or the link itself is down.
        printed_logged_in = False
        if not connection:
            if not printed_lost:
                print('',end='\n')
                print_format('''
        ██╗      ██████╗ ███████╗████████╗
        ██║     ██╔═══██╗██╔════╝╚══██╔══╝
        ██║     ██║   ██║███████╗   ██║   
        ██║     ██║   ██║╚════██║   ██║   
        ███████╗╚██████╔╝███████║   ██║   
        ╚══════╝ ╚═════╝ ╚══════╝   ╚═╝   
''', show_time=False)
                printed_lost = True

        result = login()

        # Only a rejection counts towards the limit: that means the credentials
        # (or the IP) are wrong and retrying will never help. An unreachable
        # portal is just a dead link, so keep waiting for it to come back.
        if result == LOGIN_REJECTED:
            rejected_attempt += 1
            print_format('Portal rejected the login attempt ({}/{}).'.format(
                rejected_attempt, max_login_attempt), end='\n')
            if rejected_attempt >= max_login_attempt:
                print_error('Error! Giving up after {} rejected login attempts.'.format(
                    max_login_attempt))
                print_error('Please recheck your username, password and IP address...')
                return False

        time.sleep(2 if result == LOGIN_OK else retry_delay)


def create_config():
    input_username = input('Your username (mostly student ID, without @kmitl.ac.th): ')
    input_password = getpass.getpass('Your password: ')
    input_yourIp = input('Your Public IP Address: ')

    data = {}
    if input_username != '':
        data.update({'username': input_username})
    if input_password != '':
        data.update({'password': input_password})
    if input_yourIp != '':
        data.update({'ipAddress': input_yourIp})

    with open('config.json', 'w') as config_file:
        json.dump(data, config_file, indent=4)

if __name__ == '__main__':
    # get arguments
    args = parser.parse_args()
    if args.config:
        create_config()

    if not os.path.isfile('config.json'):
        try:
            to_create = input(
                'Cannot found \'config.json\', do you want to create a new one? (Y/n): ').lower()
            if to_create not in ['n', 'no']:
                create_config()
        except EOFError:
            print('\nGood bye!')
            sys.exit(0)

    try:
        with open('config.json', 'r') as config_file:
            config = json.load(config_file)
            if 'username' in config:
                username = config['username']
            if 'password' in config:
                password = config['password']
            if 'ipAddress' in config:
                ipAddress = config['ipAddress']
    except FileNotFoundError:
        pass

    # get username and password from args
    if args.username is not None:
        username = args.username
    if args.password is not None:
        password = args.password

    # get heartbeat interval from args
    if args.ipAddress is not None:
        ipAddress = args.ipAddress

    # get maximum login attempt from args
    if args.max_attempt is not None:
        max_login_attempt = args.max_attempt

    # check if username and password are provided
    if username == '' or password == '' or username is None or password is None or ipAddress == '' or ipAddress is None:
        print('Error! Please provide username and password...')
        sys.exit(1)

    init()

    print_format('Logging in with username \'{}\'...'.format(username))

    try:
        while start():
            pass
    finally:
        logout()

    sys.exit(1)
