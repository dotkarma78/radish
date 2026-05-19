# RADISH

---

## Setup

1. Install Python's `pam` module through your package manager.
2. Clone the Git repository and change into its directory.

    ```sh
    git clone https://github.com/dotkarma78/radish.git
    cd radish
    ```

3. Make both scripts executable.

    ```shell
    chmod +x rsh rsh-gen
    ```
   
4. Execute `rsh-gen` to generate a certificate chain.

> ℹ️ **Hint:** This will create a `.radish` directory in the user's home directory containing a `crts` directory, certificate, and key file.

> ⚠️ **Warning:** Do not share the contents of `*.key`. This file should only exist on the machine the server will be hosted on. Anyone with this key can impersonate your server, decrypt network traffic, and perform man-in-the-middle attacks.

> ℹ️ **Hint:** You may share the contents of `*.crt` and copy them into the `crts` directory on systems running the client to allow them to verify your server's certificate chain and connect.

---

## Example Usage

In a privileged shell, execute:

```sh
./rsh -s
```

> ℹ️ **Hint:** The server requires root-privileges to log into users on the system. To get a privileged shell, run `su` and log in with your root password. Alternatively, use something such as `sudo` (`sudo ./rsh -s`) to execute the server in a privileged subshell.

In a second regular shell, execute:

```sh
./rsh -u <username>
```

> ℹ️ **Hint:** Replace `<username>` with a username on the system you are connecting to.