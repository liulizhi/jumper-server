#!/usr/bin/env python3
# -*- coding: utf-8 -*-

import sys
from binascii import hexlify
import pwd
import os
import re
import time
import datetime
import readline
import textwrap
import getpass
import paramiko
from paramiko.agent import AgentRequestHandler
import errno
import traceback
import struct
import fcntl
import signal
import socket
import select

import logging
from subprocess import Popen
# from Perm_host import MetadataUtil, Config
# from .enter import enter

if sys.version_info[0] < 3:
    input = raw_input
    reload(sys)
    sys.setdefaultencoding('utf8')


login_user = getpass.getuser()
socket.setdefaulttimeout(1)

try:
    remote_ip = os.environ.get('SSH_CLIENT').split()[0]
except (IndexError, AttributeError):
    remote_ip = os.popen("who -m | awk '{ print $NF }'").read().strip('()\n')

TIME_FORMAT = '%Y-%m-%d %H:%M:%S'
PRINT_NUM = 50

try:
    import termios
    import tty
except ImportError:
    print('\033[1;31m仅支持类Unix系统 Only unix like supported.\033[0m')
    time.sleep(3)
    sys.exit()


def color_print(msg, color='red', exits=False):
    """
    Print colorful string.
    颜色打印字符或者退出
    """
    color_msg = {'blue': '\033[1;36m%s\033[0m',
                 'green': '\033[1;32m%s\033[0m',
                 'yellow': '\033[1;33m%s\033[0m',
                 'red': '\033[1;31m%s\033[0m',
                 'title': '\033[30;42m%s\033[0m',
                 'info': '\033[32m%s\033[0m'}
    msg = color_msg.get(color, 'red') % msg
    print(msg)
    if exits:
        time.sleep(2)
        sys.exit()
    return msg


def write_log(f, msg):
    msg = re.sub(r'[\r\n]', '\r\n', msg)
    f.write(msg)
    f.flush()


def chown(path, user, group=''):
    if not group:
        group = user
    try:
        uid = pwd.getpwnam(user).pw_uid
        gid = pwd.getpwnam(group).pw_gid
        os.chown(path, uid, gid)
    except KeyError:
        pass


def mkdir(dir_name, username='', mode=0o755):
    """
    insure the dir exist and mode ok
    目录存在，如果不存在就建立，并且权限正确
    """
    if not os.path.isdir(dir_name):
        os.makedirs(dir_name)
        os.chmod(dir_name, mode)
    if username:
        chown(dir_name, username)


def is_port_inuse(port, ip='localhost'):
    """
    检查端口是否被占用
    """
    flag = False
    s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    try:
        s.connect((ip, int(port)))
        s.shutdown(2)
        flag = True
    except socket.timeout:
        flag = True
    except socket.error:
        flag = False
    finally:
        if s is not None:
            s.close()

    return flag


class Tty(object):
    """
    A virtual tty class
    一个虚拟终端类，实现连接ssh和记录日志，基类
    """

    def __init__(self, c, user, login_user, asset, role, login_type='ssh'):
        self.username = user
        self.asset_name = asset
        self.ip = None
        self.port = 22
        self.ssh = None
        self.channel = None
        self.asset = asset
        self.user = user
        self.login_user = login_user
        self.role = role
        self.remote_ip = ''
        self.login_type = login_type
        self.vim_flag = False
        self.ps1_pattern = re.compile('\[.*@.*\][\$#]')
        self.vim_data = ''

        self.get_log()

    @staticmethod
    def is_output(strings):
        strings = strings.decode() if isinstance(strings, bytes) else strings
        newline_char = ['\n', '\r', '\r\n']
        for char in newline_char:
            if char in strings:
                return True
        return False

    @staticmethod
    def remove_obstruct_char(cmd_str):
        """删除一些干扰的特殊符号"""
        control_char = re.compile(r'\x07 | \x1b\[1P | \r ', re.X)
        cmd_str = control_char.sub('', cmd_str.strip())
        patch_char = re.compile('\x08\x1b\[C')  # 删除方向左右一起的按键
        while patch_char.search(cmd_str):
            cmd_str = patch_char.sub('', cmd_str.rstrip())
        return cmd_str

    @staticmethod
    def deal_backspace(match_str, result_command, pattern_str, backspace_num):
        """
        处理删除确认键
        :param match_str:
        :param result_command:
        :param pattern_str:
        :param backspace_num:
        :return:
        """
        if backspace_num > 0:
            if backspace_num > len(result_command):
                result_command += pattern_str
                result_command = result_command[0:-backspace_num]
            else:
                result_command = result_command[0:-backspace_num]
                result_command += pattern_str
        del_len = len(match_str) - 3
        if del_len > 0:
            result_command = result_command[0:-del_len]
        return result_command, len(match_str)

    @staticmethod
    def deal_replace_char(match_str, result_command, backspace_num):
        '''
        处理替换命令
        '''
        str_lists = re.findall(r'(?<=\x1b\[1@)\w', match_str)
        tmp_str = ''.join(str_lists)
        result_command_list = list(result_command)
        if len(tmp_str) > 1:
            result_command_list[-backspace_num:-
                                (backspace_num - len(tmp_str))] = tmp_str
        elif len(tmp_str) > 0:
            # 不做处理
            pass
            # if result_command_list[-backspace_num] == ' ':
            #     result_command_list.insert(-backspace_num, tmp_str)
            # else:
            #     result_command_list[-backspace_num] = tmp_str
        result_command = ''.join(result_command_list)
        return result_command, len(match_str)

    def remove_control_char(self, result_command):
        """
        处理日志特殊字符
        """
        control_char = re.compile(r"""
                \x1b[ #%()*+\-.\/]. |
                \r |                                               #匹配 回车符(CR)
                (?:\x1b\[|\x9b) [ -?]* [@-~] |                     #匹配 控制顺序描述符(CSI)... Cmd
                (?:\x1b\]|\x9d) .*? (?:\x1b\\|[\a\x9c]) | \x07 |   #匹配 操作系统指令(OSC)...终止符或振铃符(ST|BEL)
                (?:\x1b[P^_]|[\x90\x9e\x9f]) .*? (?:\x1b\\|\x9c) | #匹配 设备控制串或私讯或应用程序命令(DCS|PM|APC)...终止符(ST)
                \x1b.                                              #匹配 转义过后的字符
                [\x80-\x9f] | (?:\x1b\]0.*) | \[.*@.*\][\$#] | (.*mysql>.*)      #匹配 所有控制字符
                """, re.X)
        result_command = control_char.sub('', result_command.strip())

        if not self.vim_flag:
            if result_command.startswith(
                    'vi') or result_command.startswith('fg'):
                self.vim_flag = True
            return result_command
        else:
            return ''

    def deal_command(self, str_r):
        """
            处理命令中特殊字符
        """
        str_r = self.remove_obstruct_char(str_r)

        result_command = ''  # 最后的结果
        backspace_num = 0  # 光标移动的个数
        reach_backspace_flag = False  # 没有检测到光标键则为true
        pattern_str = ''
        while str_r:
            tmp = re.match(r'\s*\w+\s*', str_r)
            if tmp:
                str_r = str_r[len(str(tmp.group(0))):]
                if reach_backspace_flag:
                    pattern_str += str(tmp.group(0))
                    continue
                else:
                    result_command += str(tmp.group(0))
                    continue

            tmp = re.match(r'\x1b\[K[\x08]*', str_r)
            if tmp:
                result_command, del_len = self.deal_backspace(
                    str(tmp.group(0)), result_command, pattern_str, backspace_num)
                reach_backspace_flag = False
                backspace_num = 0
                pattern_str = ''
                str_r = str_r[del_len:]
                continue

            tmp = re.match(r'\x08+', str_r)
            if tmp:
                str_r = str_r[len(str(tmp.group(0))):]
                if len(str_r) != 0:
                    if reach_backspace_flag:
                        result_command = result_command[0:- \
                            backspace_num] + pattern_str
                        pattern_str = ''
                    else:
                        reach_backspace_flag = True
                    backspace_num = len(str(tmp.group(0)))
                    continue
                else:
                    break

            tmp = re.match(r'(\x1b\[1@\w)+', str_r)  # 处理替换的命令
            if tmp:
                result_command, del_len = self.deal_replace_char(
                    str(tmp.group(0)), result_command, backspace_num)
                str_r = str_r[del_len:]
                backspace_num = 0
                continue

            if reach_backspace_flag:
                pattern_str += str_r[0]
            else:
                result_command += str_r[0]
            str_r = str_r[1:]

        if backspace_num > 0:
            result_command = result_command[0:-backspace_num] + pattern_str

        result_command = self.remove_control_char(result_command)
        return result_command

    def get_log(self):
        """
        Logging user command and output.
        记录用户的日志
        """

        tty_log_dir = os.path.join(self.log_dir, 'tty')
        date_today = datetime.datetime.now()
        date_start = date_today.strftime('%Y%m%d')
        time_start = date_today.strftime('%H%M%S')
        today_connect_log_dir = os.path.join(tty_log_dir, date_start)
        log_file_path = os.path.join(
            today_connect_log_dir, '%s_%s@%s_%s' %
            (self.login_user, self.username, self.asset_name, time_start))

        try:
            mkdir(os.path.dirname(today_connect_log_dir), mode=0o777)
            mkdir(today_connect_log_dir, mode=0o777)
        except OSError:
            logging.info(
                '创建目录 %s 失败，请修改%s目录权限' %
                (today_connect_log_dir, tty_log_dir))
            print('创建目录 %s 失败，请修改%s目录权限' %
                  (today_connect_log_dir, tty_log_dir))

        try:
            log_file_f = open(log_file_path + '.log', 'ab')
            log_time_f = open(log_file_path + '.time', 'ab')
            log_input_f = open(log_file_path + '.txt', 'ab')
        except IOError:
            logging.info('创建tty日志文件失败, 请修改目录%s权限' % today_connect_log_dir)
            print('创建tty日志文件失败, 请修改目录%s权限' % today_connect_log_dir)

        if self.login_type == 'ssh':  # 如果是ssh连接过来，记录connect.py的pid，web terminal记录为日志的id
            pid = os.getpid()
            self.remote_ip = remote_ip  # 获取远端IP
        else:
            pid = 0

        # log = Log(user=self.username, host=self.asset_name, remote_ip=self.remote_ip, login_type=self.login_type,
        #           log_path=log_file_path, start_time=date_today, pid=pid)
        # log.save()
        # if self.login_type == 'web':
        #     log.pid = log.id  # 设置log id为websocket的id, 然后kill时干掉websocket
        #     log.save()
        #
        # log_file_f.write('Start at %s\r\n' % datetime.datetime.now())
        # log_file_f.close()

        return log_file_f, log_time_f, log_input_f

    def agent_auth(self, transport, username):
        """
        Attempt to authenticate to the given transport using any of the private
        keys available from an SSH agent.
        """

        agent = paramiko.Agent()
        agent_keys = agent.get_keys()
        if len(agent_keys) == 0:
            return

        for key in agent_keys:
            logging.info(
                'Trying ssh-agent key %s' %
                hexlify(
                    key.get_fingerprint()))
            try:
                transport.auth_publickey(username, key)
                logging.info('... success!')
                return
            except paramiko.SSHException:
                logging.info('... nope.')

    def manual_auth(self, t, username, hostname):
        default_auth = 'p'
        auth = input(
            'Auth by (p)assword, (r)sa key, or (d)ss key? [%s] ' %
            default_auth)
        if len(auth) == 0:
            auth = default_auth

        if auth == 'r':
            default_path = os.path.join(os.environ['HOME'], '.ssh', 'id_rsa')
            path = input('RSA key [%s]: ' % default_path)
            if len(path) == 0:
                path = default_path
            try:
                key = paramiko.RSAKey.from_private_key_file(path)
            except paramiko.PasswordRequiredException:
                password = getpass.getpass('RSA key password: ')
                key = paramiko.RSAKey.from_private_key_file(path, password)
            t.auth_publickey(username, key)
        elif auth == 'd':
            default_path = os.path.join(os.environ['HOME'], '.ssh', 'id_dsa')
            path = input('DSS key [%s]: ' % default_path)
            if len(path) == 0:
                path = default_path
            try:
                key = paramiko.DSSKey.from_private_key_file(path)
            except paramiko.PasswordRequiredException:
                password = getpass.getpass('DSS key password: ')
                key = paramiko.DSSKey.from_private_key_file(path, password)
            t.auth_publickey(username, key)
        else:
            pw = getpass.getpass('Password for %s@%s: ' % (username, hostname))
            t.auth_password(username, pw)


class SshTty(Tty):
    """
    A virtual tty class
    一个虚拟终端类，实现连接ssh和记录日志
    """

    @staticmethod
    def get_win_size():
        """
        This function use to get the size of the windows!
        获得terminal窗口大小
        """
        if 'TIOCGWINSZ' in dir(termios):
            TIOCGWINSZ = termios.TIOCGWINSZ
        else:
            TIOCGWINSZ = 1074295912
        s = struct.pack('HHHH', 0, 0, 0, 0)
        x = fcntl.ioctl(sys.stdout.fileno(), TIOCGWINSZ, s)
        return struct.unpack('HHHH', x)[0:2]

    def set_win_size(self, sig, data):
        """
        This function use to set the window size of the terminal!
        设置terminal窗口大小
        """
        try:
            win_size = self.get_win_size()
            self.channel.resize_pty(height=win_size[0], width=win_size[1])
        except Exception:
            pass

    def posix_shell(self):
        """
        Use paramiko channel connect server interactive.
        使用paramiko模块的channel，连接后端，进入交互式
        """
        # 创建记录日志的文件，分为.log和.time两个文件,log表示记录日志，True
        log_file_f, log_time_f, log_input_f = self.get_log()
        # 获取文件输入流
        old_tty = termios.tcgetattr(sys.stdin)
        pre_timestamp = time.time()
        data = ''
        input_mode = False
        try:
            tty.setraw(sys.stdin.fileno())
            tty.setcbreak(sys.stdin.fileno())
            self.channel.settimeout(0.0)

            # 提供持续的输入命令行
            while True:
                try:
                    r, w, e = select.select([self.channel, sys.stdin], [], [])
                    # 锁，当有输入的时候，锁定输入进程
                    flag = fcntl.fcntl(sys.stdin, fcntl.F_GETFL, 0)
                    fcntl.fcntl(
                        sys.stdin.fileno(),
                        fcntl.F_SETFL,
                        flag | os.O_NONBLOCK)
                except Exception:
                    pass

                if self.channel in r:
                    try:
                        x = self.channel.recv(10240)
                        if len(x) == 0:
                            break
                        # 当有vim编辑文件时，记录相应信息
                        if self.vim_flag:
                            self.vim_data += x.decode()
#                             print self.vim_data,"VIM"
                        index = 0
                        len_x = len(x)
                        # 作用?
                        # 将命令输入--》 命令行？
                        while index < len_x:
                            try:
                                n = os.write(sys.stdout.fileno(), x[index:])
                                sys.stdout.flush()
                                index += n
                            except OSError as msg:
                                if msg.errno == errno.EAGAIN:
                                    continue
                        # sys.stdout.write(x)
                        # sys.stdout.flush()
                        now_timestamp = time.time()
                        # round四舍五入，保留一位小数点 5.667 --> 6.0,可以指定保留小数位数
                        # routd(num, 4)表示保留4位有效数字
#                         log_time_f.write('%s %s\n' % (round(now_timestamp - pre_timestamp, 4), len(x)))
                        # 将信息写入到time日志文件中
                        log_time_f.write(
                            ('%s %s\n' %
                             (round(
                                 now_timestamp -
                                 pre_timestamp,
                                 4),
                                 len(x))).encode())
                        log_time_f.flush()
                        # 将操作信息写入到log日志记录文件中
                        # flush刷新文件，将缓存中的信息写入到文件中
                        log_file_f.write(x)
                        log_file_f.flush()
                        pre_timestamp = now_timestamp
                        log_file_f.flush()

                        # 持续输入，如果位输入模式，并且没有输入enter等
                        if input_mode and not self.is_output(x):
                            data += x.decode()

                    except socket.timeout:
                        pass

                if sys.stdin in r:
                    try:
                        x = os.read(sys.stdin.fileno(), 4096)
                    except OSError:
                        pass
                    input_mode = True
                    if str(x.decode()) in ['\r', '\n', '\r\n']:
                        if self.vim_flag:
                            match = self.ps1_pattern.search(self.vim_data)
                            if match:
                                self.vim_flag = False
                                data = self.deal_command(data)[0:200]
                                if len(data) > 0:
                                    now_timestamp = datetime.datetime.now().strftime(TIME_FORMAT)
                                    log_input_f.write(
                                        ('%s: %s\n' %
                                         (now_timestamp, data)).encode())
                                    log_input_f.flush()
                                    # TtyLog(log=log, datetime=datetime.datetime.now(), cmd=data).save()
                        else:
                            data = self.deal_command(data)[0:200]
                            if len(data) > 0:
                                now_timestamp = datetime.datetime.now().strftime(TIME_FORMAT)
                                log_input_f.write(
                                    ('%s: %s\n' %
                                     (now_timestamp, data)).encode())
                                log_input_f.flush()
                                # TtyLog(log=log, datetime=datetime.datetime.now(), cmd=data).save()
                        data = ''
                        self.vim_data = ''
                        input_mode = False

                    if len(x) == 0:
                        break
                    self.channel.send(x)

        finally:
            termios.tcsetattr(sys.stdin, termios.TCSADRAIN, old_tty)
            log_file_f.write(
                ('End time is %s' %
                 datetime.datetime.now()).encode())
            log_file_f.close()
            log_time_f.close()
            log_input_f.close()
            # log.is_finished = True
            # log.end_time = datetime.datetime.now()
            # log.save()
        # except:
        #     pass

    def connect(self):
        """
        Connect server.
        连接服务器
        """
        # 发起ssh连接请求 Make a ssh connection
#         print self.asset,'==================='
#         ssh = self.get_connection()
#
#         transport = ssh.get_transport()
#         transport.set_keepalive(30)
#         transport.use_compression(True)

        # 重写认证流程
        # now connect
        try:
            sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
            sock.connect((self.asset, self.port))
        except Exception as e:
            print('*** Connect failed: ' + str(e))
            return

        try:
            t = paramiko.Transport(sock)
            try:
                t.start_client()
            except paramiko.SSHException:
                print('*** SSH negotiation failed.')
                return

            # 不需要从文件里面读取key
            # try:
            #     keys = paramiko.util.load_host_keys(os.path.expanduser('~/.ssh/known_hosts'))
            # except IOError:
            #     try:
            #         keys = paramiko.util.load_host_keys(os.path.expanduser('~/ssh/known_hosts'))
            #     except IOError:
            #         print('*** Unable to open host keys file')
            #         keys = {}

            # # check server's host key -- this is important.
            # key = t.get_remote_server_key()
            # if self.asset not in keys:
            #     print('*** WARNING: Unknown host key!')
            # elif key.get_name() not in keys[self.asset]:
            #     print('*** WARNING: Unknown host key!')
            # elif keys[self.asset][key.get_name()] != key:
            #     print('*** WARNING: Host key has changed!!!')
            #     # sys.exit(1)
            #     return
            # else:
            #     print('*** Host key OK.')

            # get username
#             if self.user == '':
#                 default_username = getpass.getuser()
#                 username = input('Username [%s]: ' % default_username)
#                 if len(username) == 0:
#                     username = default_username

            try:
                self.agent_auth(t, self.username)
            except Exception as e:
                print('密钥认证失败，请检查您的密钥： {}'.format(e))
            if not t.is_authenticated():
                try:
                    self.manual_auth(t, self.user, self.asset)
                except BaseException:
                    pass
            if not t.is_authenticated():
                print('*** Authentication failed. :(')
                t.close()
                # sys.exit(1)
                return
            global channel
            win_size = self.get_win_size()
            self.channel = channel = t.open_session()
            # Forward local agent
            # Commands executed after this point will see the forwarded agent
            # on the remote end.
            AgentRequestHandler(channel)

        # 获取连接的隧道并设置窗口大小 Make a channel and set windows size

        # self.channel = channel = ssh.invoke_shell(height=win_size[0], width=win_size[1], term='xterm')
#         self.channel = channel = transport.open_session()
            channel.get_pty(
                term='xterm',
                height=win_size[0],
                width=win_size[1])
            channel.invoke_shell()
            try:
                signal.signal(signal.SIGWINCH, self.set_win_size)
            except BaseException:
                pass

            self.posix_shell()

            # Shutdown channel socket
            channel.close()
#             ssh.close()
        except Exception as e:
            print('*** Caught exception: ' + str(e.__class__) + ': ' + str(e))
            traceback.print_exc()
            try:
                t.close()
            except BaseException:
                pass
            # sys.exit(1)
            return


def is_ip_addr(ip):
    reg = re.compile("^(1\\d{2}|2[0-4]\\d|25[0-5]|[1-9]\\d|[1-9])\\."
                     "(1\\d{2}|2[0-4]\\d|25[0-5]|[1-9]\\d|\\d)\\."
                     "(1\\d{2}|2[0-4]\\d|25[0-5]|[1-9]\\d|\\d)\\."
                     "(1\\d{2}|2[0-4]\\d|25[0-5]|[1-9]\\d|\\d)$")

    return bool(reg.match(ip))


def enter(print_over, nav, option):

    gid_pattern = re.compile(r'^g\d+$')

    # 可以按回车了
    if option in ['\n', '']:
        return

    if option in ['L', 'l']:
        # 列出用户密钥
        if option == 'l':
            print(os.popen('ssh-add -l').read())
        else:
            print(os.popen('ssh-add -L').read())
        return

    if option in ['#hostname']:
        # 列出当前跳板机的主机名
        print(os.popen('hostname').read())
        return

    if option in ['P', 'p']:
        if print_over:
            nav.search()
            host_index = 0
            print_over = False
            nav.print_host()
        return

    if option in ['R', 'r']:
        rdp_ip = input('请输入您要登录的机器IP：')
        if not is_ip_addr(rdp_ip):
            print('IP地址输入有误.')
        try:
            rdp = RDP(login_user, rdp_ip)
            command = rdp.get_login_command()
        except Exception as e:
            print('RDP脚本初始化异常: %s' % e)
        print(
            '您已进入RDP模式，RDP服务器地址:\033[32m%s:%s\033[0m, 请用登录工具连接至\033[32m%s:%s\033[0m进行登录.' %
            (rdp_ip, '3389', rdp.rdp_domain, rdp.port))
        print()
        try:
            ps = Popen(command, shell=True, stdout=None, stderr=None)
            ps.wait()
        except KeyboardInterrupt:
            print()
            print('您已退出RDP模式.')

    if option.startswith('/') or gid_pattern.match(option):
        if print_over:
            nav.search(option.lstrip('/'))
            host_index = 0
            print_over = False
        return

    elif option in ['H', 'h']:
        nav.print_nav()
        return

    elif option in ['Q', 'q', 'exit']:
        sys.exit()

    else:
        user = login_user
        if option.isdigit():
            if not 0 < int(option) <= host_index:
                color_print('Wrong number. Please check!!')
                nav.print_nav()
            host = nav.search_result[int(option) - 1].get('hostname')
        else:
            # <user>@<host>
            if option.count('@'):
                user = option.split('@')[0]
                host = option.split('@')[1]
            else:
                host = option

        # host只能是IP或者符合规则的主机名 #
        if not check_hostname(host):
            color_print('Host %r not exist!!' % host)
            nav.print_nav()

        print('Connecting to %s@%s' % (user, host))
        ssh_tty = SshTty(
            user,
            login_user,
            host,
            "/home/%s/.ssh/id_rsa" %
            user)
        ssh_tty.connect()
        print_over = True


class RDPException(Exception):

    pass


class RDP(object):

    def __init__(self, c, login_user, ip):
        self.c = c
        self.user = login_user
        self.rdp_ip = ip
        self.port = self.get_available_port()

    def get_login_command(self):
        """
        command example:
        rdpy-rdpmitm.py -o /rc/log/rc-jumpser/rdp/20170822/liuzhenwu -l 4000 \
        -k /rc/conf/ssl/ca.key -c /rc/conf/ssl/ca.crt -r 10.200.3.28:3389
        """
        try:
            log_dir = self.get_log_dir()
        except Exception as e:
            raise RDPException('创建RDP日志文件夹失败: %s' % str(e))
        command = "%s -o %s -l %s -k %s -c %s -r %s:3389" % (
            self.c.rdp_script, log_dir, self.c.port, self.c.rdp_key, self.c.rdp_crt, self.rdp_ip)
        return command

    def get_available_port(self):
        for port in range(self.c.rdp_port[0], self.c.rdp_port[1] + 1):
            if not is_port_inuse(int(port)):
                return port
        else:
            raise RDPException('获取RDP连接端口失败.')

    def get_log_dir(self):
        """
        $LOGPATH/rdp/$date/$user/
        """
        rdp_log_dir = os.path.join(self.log_dir, 'rdp')
        mkdir(rdp_log_dir, mode=0o777)

        date_today = datetime.datetime.now()
        date_start = date_today.strftime('%Y%m%d')
        today_connect_log_dir = os.path.join(rdp_log_dir, date_start)
        mkdir(today_connect_log_dir, mode=0o777)
        user_dir = os.path.join(today_connect_log_dir, self.user)
        mkdir(user_dir, mode=0o777)
        return user_dir


class Nav(object):
    """
    导航提示类
    """

    def __init__(self, user):
        self.perm_host = [
            {
                "hostname": "host1-v-sendal.com",
                "ip": "10.10.10.10",
            },
            {
                "hostname": "host2-a-sendal.com",
                "ip": "10.10.10.11",
            },
            {
                "hostname": "host3-o-sendal.com",
                "ip": "10.10.10.12",
            },
            {
                "hostname": "host4-a-sendal.com",
                "ip": "10.10.10.13",
            },
            {
                "hostname": "host5-o-sendal.com",
                "ip": "10.10.10.14",
            },
            {
                "hostname": "host6-o-sendal.com",
                "ip": "10.10.10.15",
            },
        ]
        self.user = user
        self.search_result = []
        self.user_perm = {}

    @staticmethod
    def print_nav():
        """
        Print prompt
        打印提示导航
        """

        msg = """\n\033[1;32m###    欢迎使用跳板机系统   ### \033[0m
        1) 输入 \033[32m主机名\033[0m 或 \033[32mIP\033[0m 直接登录.
        2) 输入 \033[32mP/p\033[0m 显示您有权限的主机.
        3) 输入 \033[32m/\033[0m + \033[32m关键字 \033[0m进行搜索.
        4) 输入 \033[32mR/r\033[0m 进入\033[32mRDP\033[0m模式.
        5) 输入 \033[32mL/l\033[0m 查看您的公钥/私钥.
        6) 输入 \033[32mH/h\033[0m 帮助.
        7) 输入 \033[32mQ/q\033[0m 退出.
        """

        print(textwrap.dedent(msg))

    def search(self, str_r=''):
        str_r = str_r.strip()
        if not str_r:
            print('Searching for hosts...')
        else:
            print('Searching for "%s"...' % str_r)

        self.search_result = sorted(
            self.perm_host,
            key=lambda hn: hn.get("hostname")
        )

        if str_r != '':
            self.search_result = list(
                filter(
                    lambda host: host.get("hostname").lower().count(
                        str_r.lower()),
                    self.search_result))

    def print_host(self, start=0):
        host_num = len(self.search_result)

        while True:
            end = min(host_num, start + PRINT_NUM)

            for i, host in enumerate(self.search_result[start: end]):
                hostname = host.get("hostname")
                if hostname.lower().count('-v-'):
                    host_type = '[OpenStack]'
                elif hostname.lower().count('-a-'):
                    host_type = '[Aliyun]'
                else:
                    host_type = '[Other]\t'  # 添加'\t'对齐

                print("[%s]\t\t%s\t\t%s\t\t%s" %
                      (i + start + 1, host_type, host.get("ip"), hostname))

            if end >= host_num:
                print('Complete!\n')
                break
            else:
                start = end
                input("\033[1;32mPress [ENTER] to continue...\033[0m ").strip()


def check_hostname(hostname):
    if hostname.count('.') == 3 or hostname.count(
            '-') >= 2 or hostname.endswith('host.dataengine.com'):
        return True
    else:
        return False


def main():
    """
    主程序
    """
    if not login_user:  # 判断用户是否存在
        color_print('没有该用户，或许你是以root运行的 No that user.', exits=True)

    nav = Nav(login_user)
    nav.print_nav()

    # host_index = 0
    print_over = True

    try:
        while True:
            # if not print_over:
            #     print_over = nav.print_host(host_index)
            #     host_index += 100

            try:
                option = input(
                    "\033[1;32mOption or Host>:\033[0m ").strip()
                # option = input(
                #     "\033[1;32mPress [ENTER] to continue...\033[0m ").strip()
            except EOFError:
                nav.print_nav()
                continue
            except KeyboardInterrupt:
                sys.exit(0)
            enter(print_over, nav, option)

    except IndexError as e:
        color_print(e)
        sys.exit(1)


if __name__ == '__main__':
    main()