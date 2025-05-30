# runner-gateway

A simple gateway for interacting with model runner APIs (i.e. Ollama) that provides TLS and OAuth2.0 authentication with PASETO token validation.

## Features

- **Authentication**: Secure access to the Ollama API using PASETO tokens.
- **Configuration**: Easy configuration through a YAML file.
- **Logging**: Detailed logging for monitoring and debugging.
- **SSL/TLS Support**: SSL/TLS support for secure communication.

## Installation

### Preparation

Generate a PASETO key pair:

```bash
go run tools/paseto -action=asymmetric
```

This will generate `paseto.key` and `paseto.pub` files in the `./settings` directory (this is what the server is configured to look at by default).

**Note**: If you have an existing private / public key pair, you can use your existing public key for validation instead by adjusting the configuration accordingly. The private key is only used for generating tokens via the tools provided, but it is not required for runtime gateway operation.

## Tools

### Generate Asymmetric (Private/Public) Key Pair

```bash
go run tools/paseto -action=asymmetric
```

### Generate Symmetric Key

```bash
go run tools/paseto -action=symmetric
```

### Generate Private PASETO Token Signed by Public Key

```bash
go run tools/paseto -action=private
```

### Generate Public PASETO Token Signed by Public Key

```bash
go run tools/paseto -action=public
```
