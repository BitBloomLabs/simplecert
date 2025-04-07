# Simple Cert

Simple Cert is a basic private Certificate Authority (CA) implemented in Go. It provides functionality for:

* Generating a root CA certificate.
* Signing Certificate Signing Requests (CSRs).
* Generating Certificate Revocation Lists (CRLs).

**Important: This project is under development and should not be used in production environments yet.**

## Getting Started

### Prerequisites

* Go 1.18 or later

### Installation

1.  Clone the repository:

    ```bash
    git clone [https://github.com/BitBloomLabs/simplecert.git](https://www.google.com/search?q=https://github.com/BitBloomLabs/simplecert.git)
    ```

2.  Navigate to the project directory:

    ```bash
    cd simplecert
    ```

3.  Build the application:

    ```bash
    go build -o simplecertd ./cmd/simplecertd/main.go
    ```

### Running the CA

1.  Run the `simplecertd` executable:

    ```bash
    ./simplecertd
    ```

    This will start the CA server. By default, it listens on `localhost:8080`.

### Using the CA (Example)

#### Signing a Certificate Signing Request (CSR)

1.  Generate a CSR (e.g., using `openssl`):

    ```bash
    openssl genrsa -out client.key 2048
    openssl req -new -key client.key -out client.csr -subj "/CN=example.com"
    ```

2.  Submit the CSR to the CA:

    ```bash
    curl -X POST -H "Content-Type: application/x-pem-file" --data-binary @client.csr http://localhost:8080/sign > client.crt
    ```

#### Fetching the CRL

```bash
curl http://localhost:8080/crl > crl.der