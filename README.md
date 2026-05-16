# Setup

1. Clone the Git repository and change into its directory.

```sh
git clone https://github.com/dotkarma78/radish.git
cd radish
```

2. Generate a key and certificate for OpenSSL/TLS.

```sh
openssl req -x509 -newkey ec -pkeyopt 'ec_paramgen_curve:P-256' -days 365 -keyout key.pem -out cert.pem -noenc -subj "/CN=127.0.0.1" -addext "subjectAltName=IP:127.0.0.1,DNS:localhost"
```

This command will create two files named `key.pem` and `cert.pem` needed for encryption and verification respectively. The certificate will only be valid for host names `127.0.0.1` and `localhost`.

> ⚠️ **Warning:** Do not share the contents of `key.pem` to anyone. The file should only exist on the machine the server will be running on. If you need a second server on a different machine, regenerate a key and certificate.

3. Make the script executable.

```sh
chmod +x ./radish
```

## Example Usage

1. In a privileged shell, run:

```sh
./radish -s
```

This will start a server bound to `127.0.0.1:8078` by default.
The server requires privileged permissions to switch users and drop to lower permissions again.

> ℹ️ **Hint:** To get a privileged shell, run `su` and log in with your root user's password. This will spawn a shell under your root user. Alternatively, use something such as `sudo` (`sudo ./radish -s`) to run the script on a privileged sub-shell.

2. In a second, regular shell, run:

```sh
./radish -u <username>
```

This will connect a client to `127.0.0.1:8078` by default.
Replace `<username>` with a user on the system the server is running on.
