#!/usr/bin/env python3

from argparse import ArgumentParser, Namespace
from getpass import getpass
from os import chdir, environ, execv, kill, listdir, path, read, setgid, setuid, waitpid, WNOHANG, write
from pam import pam
from pty import fork
from pwd import getpwnam, struct_passwd
from selectors import DefaultSelector, EVENT_READ, SelectorKey
from signal import SIGHUP
from socket import gethostname, SO_REUSEADDR, socket as Socket, SOL_SOCKET
from ssl import PROTOCOL_TLS_CLIENT, PROTOCOL_TLS_SERVER, SSLContext, SSLError, SSLSocket
from sys import stdin, stdout
from termios import tcgetattr, TCSAFLUSH, tcsetattr
from tty import setraw
from typing import NamedTuple

BUFFER_SIZE: int = 4096

argument_parser: ArgumentParser = ArgumentParser()
argument_parser.add_argument('-H', '--host', default = '127.0.0.1', type = str)
argument_parser.add_argument('-p', '--port', default = 8078, type = int)
argument_parser.add_argument('-s', '--server-mode', action = 'store_true')
argument_parser.add_argument('-u', '--username', type = str)
arguments: Namespace = argument_parser.parse_args()

server_host: str = arguments.host
server_port: int = arguments.port
server_endpoint: tuple[str, int] = (server_host, server_port)

server_mode: bool = arguments.server_mode
client_mode: bool = not server_mode

username: str = arguments.username

STDIN: int = stdin.fileno()
STDOUT: int = stdout.fileno()

HOST: str = gethostname()

HOME: str = environ['HOME']
RADISH_DIRECTORY: str = f'{HOME}/.radish'
CERTIFICATE_DIRECTORY: str = f'{RADISH_DIRECTORY}/crts'

CERTIFICATE_FILE: str = f'{RADISH_DIRECTORY}/{HOST}.crt'
KEY_FILE: str = f'{RADISH_DIRECTORY}/{HOST}.key'

missing_files: list[str] = []

if path.exists(CERTIFICATE_FILE):
    message = f'\x1b[32m[+]\x1b[0m Found certificate file at "{CERTIFICATE_FILE}".\n'.encode()
    write(STDOUT, message)
elif not path.exists(CERTIFICATE_FILE):
    missing_files.append(CERTIFICATE_FILE)
    message = f'\x1b[33m[!]\x1b[0m Missing certificate file at "{CERTIFICATE_FILE}".\n'.encode()
    write(STDOUT, message)

if path.exists(KEY_FILE):
    message = f'\x1b[32m[+]\x1b[0m Found key file at "{KEY_FILE}".\n'.encode()
    write(STDOUT, message)
elif not path.exists(KEY_FILE):
    missing_files.append(KEY_FILE)
    message = f'\x1b[33m[!]\x1b[0m Missing key file at "{KEY_FILE}".\n'.encode()
    write(STDOUT, message)

if missing_files:
    message = f'\x1b[31m[-]\x1b[0m Missing certificate chain for SSL/TLS.\n'.encode()
    write(STDOUT, message)
    message = f'\x1b[34m[i]\x1b[0m Use "rsh-gen" to generate one.\n'.encode()
    write(STDOUT, message)
    exit()

if server_mode:
    server_socket: Socket = Socket()
    server_socket.setsockopt(SOL_SOCKET, SO_REUSEADDR, 1)
    server_socket.setblocking(False)
    server_socket.bind(server_endpoint)
    server_socket.listen()

    selector: DefaultSelector = DefaultSelector()
    selector.register(server_socket, EVENT_READ, 'conn')

    class Endpoint(NamedTuple):
        host: str
        port: int

    client_endpoints: dict[Socket, Endpoint] = {}
    client_processes: dict[Socket, tuple[int, int]] = {}
    client_sockets: dict[int, Socket] = {}

    tls_context: SSLContext = SSLContext(PROTOCOL_TLS_SERVER)
    tls_context.load_cert_chain(CERTIFICATE_FILE, KEY_FILE)

    message = f'\x1b[34m[i]\x1b[0m Started server at {server_host}:{server_port}.\n'.encode()
    write(STDOUT, message)

    try:
        while True:
            ready_file_objects: list[tuple[SelectorKey, int]] = selector.select()
            key: SelectorKey; mask: int
            for key, mask in ready_file_objects:
                data: str = key.data
                if data == 'conn':
                    client_socket: Socket; client_endpoint: Endpoint
                    client_socket, client_endpoint = server_socket.accept()

                    client_host: str; client_port: int
                    client_host, client_port = client_endpoint

                    message = f'\x1b[34m[i]\x1b[0m TCP/IP connection established with client from {client_host}:{client_port}.\n'.encode()
                    write(STDOUT, message)

                    try:
                        client_socket: SSLSocket = tls_context.wrap_socket(client_socket, True)
                    except SSLError:
                        message = f'\x1b[34m[i]\x1b[0m SSL/TLS certificate verification failed by {client_host}:{client_port}.\n'.encode()
                        write(STDOUT, message)
                        client_socket.close()
                        message = f'\x1b[34m[i]\x1b[0m TCP/IP connection closed by client from {client_host}:{client_port}.\n'.encode()
                        write(STDOUT, message)
                        continue
                    client_socket.setblocking(False)

                    message = f'\x1b[34m[i]\x1b[0m SSL/TLS handshake completed with client from {client_host}:{client_port}.\n'.encode()
                    write(STDOUT, message)

                    selector.register(client_socket, EVENT_READ, 'auth')
                    client_endpoints[client_socket] = client_endpoint

                elif data == 'auth':
                    client_socket: SSLSocket = key.fileobj
                    try:
                        credentials: bytes = client_socket.recv(BUFFER_SIZE)
                    except ConnectionResetError:
                        client_socket.close()
                        client_host: str; client_port: int
                        client_host, client_port = client_endpoints[client_socket]
                        selector.unregister(client_socket)
                        client_endpoints.pop(client_socket)
                        message = f'\x1b[33m[!]\x1b[0m Client from {client_host}:{client_port} failed to provide credentials.\n'.encode()
                        write(STDOUT, message)
                        message = f'\x1b[34m[i]\x1b[0m TCP/IP connection closed by client from {client_host}:{client_port}.\n'.encode()
                        write(STDOUT, message)
                        continue
                    username: str; password: str
                    username, password = credentials.decode().split('\n', 1)

                    pam_authenticator: pam = pam()
                    authenticated: bool = pam_authenticator.authenticate(username, password)
                    denied: bool = not authenticated
                    if authenticated:
                        client_host: str; client_port: int
                        client_host, client_port = client_endpoints[client_socket]
                        message = f'\x1b[32m[+]\x1b[0m PAM authenticatied client from {client_host}:{client_port}.\n'.encode()
                        write(STDOUT, message)

                        process_identifier: int; master_file_descriptor: int
                        process_identifier, master_file_descriptor = fork()
                        if process_identifier == 0:
                            password_entry: struct_passwd = getpwnam(username)
                            group_identifier: int = password_entry.pw_gid
                            user_identifier: int = password_entry.pw_uid

                            home: str = password_entry.pw_dir
                            mail: str = f'/var/mail/{username}'
                            shell: str = password_entry.pw_shell
                            user: str = username

                            environ['HOME'] = home
                            environ['LOGNAME'] = username
                            environ['MAIL'] = mail
                            environ['PWD'] = home
                            environ['SHELL'] = shell
                            environ['USER'] = username

                            chdir(home)

                            setgid(group_identifier)
                            setuid(user_identifier)

                            execv(shell, [shell, '-il'])

                        elif process_identifier != 0:
                            selector.modify(client_socket, EVENT_READ, 'in')
                            selector.register(master_file_descriptor, EVENT_READ, 'out')

                            client_processes[client_socket] = (process_identifier, master_file_descriptor)
                            client_sockets[master_file_descriptor] = client_socket

                    elif denied:
                        client_host: str; client_port: int
                        client_host, client_port = client_endpoints[client_socket]

                        message: bytes = f'\x1b[33m[!]\x1b[0m PAM authentication denied with client from {client_host}:{client_port}.\n'.encode()
                        write(STDOUT, message)

                        client_socket.close()
                        selector.unregister(client_socket)
                        client_endpoints.pop(client_socket)

                        message = f'\x1b[34m[i]\x1b[0m TCP/IP connection closed with client from {client_host}:{client_port}.\n'.encode()
                        write(STDOUT, message)

                elif data == 'in':
                    client_socket: SSLSocket = key.fileobj
                    master_file_descriptor: int = client_processes[client_socket][1]

                    client_host: str; client_port: int
                    client_host, client_port = client_endpoints[client_socket]

                    buffer: bytes = client_socket.recv(BUFFER_SIZE)
                    if buffer:
                        write(master_file_descriptor, buffer)
                    elif not buffer:
                        message = f'\x1b[34m[i]\x1b[0m TCP/IP connection closed by client from {client_host}:{client_port}.\n'.encode()
                        write(STDOUT, message)

                        process_identifier: int = client_processes[client_socket][0]

                        client_socket.close()
                        kill(process_identifier, SIGHUP)
                        waitpid(process_identifier, WNOHANG)

                        selector.unregister(client_socket)
                        selector.unregister(master_file_descriptor)

                        client_endpoints.pop(client_socket)
                        client_processes.pop(client_socket)
                        client_sockets.pop(master_file_descriptor)

                elif data == 'out':
                    master_file_descriptor: int = key.fd
                    client_socket: SSLSocket = client_sockets[master_file_descriptor]
                    client_host: str; client_port: int
                    client_host, client_port = client_endpoints[client_socket]
                    try:
                        buffer: bytes = read(master_file_descriptor, BUFFER_SIZE)
                        client_socket.sendall(buffer)
                    except OSError:
                        message = f'\x1b[34m[i]\x1b[0m TCP/IP connection closed by client from {client_host}:{client_port}.\n'.encode()
                        write(STDOUT, message)

                        process_identifier: int = client_processes[client_socket][0]

                        client_socket.close()
                        kill(process_identifier, SIGHUP)
                        waitpid(process_identifier, WNOHANG)

                        selector.unregister(client_socket)
                        selector.unregister(master_file_descriptor)

                        client_endpoints.pop(client_socket)
                        client_processes.pop(client_socket)
                        client_sockets.pop(master_file_descriptor)

    except KeyboardInterrupt:
        client_socket: Socket
        for client_socket in client_sockets.values():
            client_socket.sendall(b'\r\r')
        message = f'\r\x1b[34m[i]\x1b[0m Stopped server at {server_host}:{server_port}.\n'.encode()
        write(STDOUT, message)

elif client_mode:
    socket: Socket = Socket()
    socket.connect(server_endpoint)

    message: bytes = f'\x1b[34m[i]\x1b[0m TCP/IP connection established with server from {server_host}:{server_port}.\n'.encode()
    write(STDOUT, message)

    tls_context: SSLContext = SSLContext(PROTOCOL_TLS_CLIENT)
    tls_context.load_verify_locations(CERTIFICATE_FILE)
    certificate_file_name: str
    for certificate_file_name in listdir(CERTIFICATE_DIRECTORY):
        certificate_file: str = f'{CERTIFICATE_DIRECTORY}/{certificate_file_name}'
        tls_context.load_verify_locations(certificate_file)

    socket: SSLSocket = tls_context.wrap_socket(socket, server_hostname = server_host)

    message = f'\x1b[34m[i]\x1b[0m SSL/TLS handshake completed with server from {server_host}:{server_port}.\n'.encode()
    write(STDOUT, message)

    prompt: str = f'\x1b[35m[?]\x1b[0m {username}\'s password: '
    try:
        password: str = getpass(prompt)
    except KeyboardInterrupt:
        socket.close()
        message = f'\r\x1b[34m[i]\x1b[0m TCP/IP connection closed with server from {server_host}:{server_port}.\n'.encode()
        write(STDOUT, message)
        exit()

    socket.sendall(f'{username}\n{password}'.encode())
    buffer: bytes = socket.recv(BUFFER_SIZE)
    if buffer:
        message = f'\x1b[32m[+]\x1b[0m PAM authenticatied by server from {server_host}:{server_port}.\n'.encode()
        write(STDOUT, message)
    elif not buffer:
        socket.close()

        message: bytes = f'\x1b[33m[!]\x1b[0m PAM authentication denied by server from {server_host}:{server_port}.\n'.encode()
        write(STDOUT, message)
        message = f'\r\x1b[34m[i]\x1b[0m TCP/IP connection closed by server from {server_host}:{server_port}.\n'.encode()
        write(STDOUT, message)

        exit()

    socket.setblocking(False)

    selector: DefaultSelector = DefaultSelector()
    selector.register(socket, EVENT_READ, 'in')
    selector.register(STDIN, EVENT_READ, 'out')

    old_tty_attributes: list[int | list[bytes | int]] | list[int | list[bytes]] | list[int | list[int]] = tcgetattr(STDIN)
    setraw(STDIN)

    while True:
        ready_file_objects: list[tuple[SelectorKey, int]] = selector.select()
        key: SelectorKey; mask: int
        for key, mask in ready_file_objects:
            data: str = key.data
            if data == 'in':
                buffer: bytes = socket.recv(BUFFER_SIZE)
                if buffer and buffer != b'\r\r':
                    write(STDOUT, buffer)
                elif buffer == b'\r\r':
                    socket.close()

                    selector.unregister(socket)
                    selector.unregister(STDIN)

                    tcsetattr(STDIN, TCSAFLUSH, old_tty_attributes)

                    message = f'\r\x1b[34m[i]\x1b[0m TCP/IP connection closed by server from {server_host}:{server_port}.\n'.encode()
                    write(STDOUT, message)

                    exit()

                elif not buffer:
                    socket.close()
                    selector.unregister(socket)
                    selector.unregister(STDIN)
                    tcsetattr(STDIN, TCSAFLUSH, old_tty_attributes)

                    message = f'\r\x1b[34m[i]\x1b[0m TCP/IP connection closed with server from {server_host}:{server_port}.\n'.encode()
                    write(STDOUT, message)

                    exit()

            elif data == 'out':
                buffer: bytes = read(STDIN, BUFFER_SIZE)
                socket.sendall(buffer)
