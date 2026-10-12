# NetCat V3

A Python TCP client/server networking project inspired by Netcat, built with Python's standard library.

> **Project status:** Educational project. Review and test the implementation before using it outside a local lab or another environment where you have permission.

## Features

The project is intended to provide features such as:

- TCP client/server communication
- A length-prefixed message protocol
- Multi-client handling and client identification
- Direct messaging and broadcast (server-side, if implemented)
- Connection and heartbeat monitoring (if implemented)
- File transfer with progress reporting and SHA-256 verification (if implemented)
- Optional TLS and username/password authentication (if implemented)
- Rate limiting, logging, and command-line configuration (if implemented)
- Built-in self-tests

Only advertise features that are implemented and tested in the version you publish.

## Requirements

- Python 3.9 or newer
- No third-party packages are required if the implementation uses only the Python standard library

## Getting Started

### 1. Get the repository

If Git is installed:

```bash
git clone https://github.com/YOUR_USERNAME/NetCat-V3.git
cd NetCat-V3
```

Alternatively, use GitHub's **Code** menu to download the repository, then open the extracted project folder.

Replace `YOUR_USERNAME` with your GitHub username.

### 2. Check Python

```bash
python --version
```

### 3. Run the built-in tests

```bash
python netcat.py --self-test
```

If your current code does not yet support `--self-test`, check the available options:

```bash
python netcat.py --help
```

### 4. Local TCP test

Open one terminal in the project folder and start the server:

```bash
python netcat.py -l -t 127.0.0.1 -p 5555 --interactive
```

Open a second terminal in the same folder and start a client:

```bash
python netcat.py -t 127.0.0.1 -p 5555
```

`127.0.0.1` means the same computer, so this is a local test. The exact options and commands depend on the implementation in `netcat.py`.

## Security Notes

- Test only on systems and networks where you have permission.
- Do not commit real passwords, private keys, certificates containing private material, or `.env` files.
- TLS requires correctly configured certificates and keys.
- Do not treat this educational project as production-ready without a security review.
- TCP and UDP have different reliability and connection semantics; this repository's documented behavior should match the actual implementation.

## Project Structure

```text
NetCat-V3/
├── netcat.py
├── README.md
├── LICENSE
├── requirements.txt
└── .gitignore
```

## Testing

Run the built-in tests, if available:

```bash
python netcat.py --self-test
```

Also test client/server communication in two local terminal windows before publishing.

## License

This project is released under the MIT License. See `LICENSE`.
