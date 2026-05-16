# Installation

Clone the git repository and change into it:

```sh
git clone https://github.com/dotkarma78.git
cd radish
```

Install `git` if not already.

Next, make the Python script executable by running: 

```sh
chmod +x radish
```

# Example Usage

In a privileged shell, execute:

```sh
./radish -s
```

In a second regular one:

```sh
./radish -u <username>
```

Replace `<username>` with a username on your system.

## SECURITY WARNING
This tool does not encrypt network traffic and sends all data as plaintext. Using this outside of localhost risks data theft with major consequences. This tool is unsafe for production or real usage and should not be used outside of isolated environments. By default, the script binds to localhost.
