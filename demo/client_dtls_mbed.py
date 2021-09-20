
from mbedtls import tls

import datetime as dt
from mbedtls import hashlib
from mbedtls import pk
from mbedtls import x509

import socket
from contextlib import suppress
import multiprocessing as mp


def block(callback, *args, **kwargs):
    while True:
        with suppress(tls.WantReadError, tls.WantWriteError):
            return callback(*args, **kwargs)



if __name__ == "__main__":

    pem = '-----BEGIN CERTIFICATE-----\nMIIC+jCCAeKgAwIBAgIDEjRWMA0GCSqGSIb3DQEBCwUAMBUxEzARBgNVBAMMClRy\ndXN0ZWQgQ0EwHhcNMjEwOTE3MDUzMDAyWhcNMjExMjE2MDUzMDAyWjAVMRMwEQYD\nVQQDDApUcnVzdGVkIENBMIIBIjANBgkqhkiG9w0BAQEFAAOCAQ8AMIIBCgKCAQEA\nz3d5m5PgUSlJKQA7+v7NTKsO+0/AF2098fIBpXw9VbSg64o22hylyhfsghqjGJxo\n5jPRHDL6Op5cp89fjOix2Hild4zlS847SwnEPgEZmBln8nUWIqIrTLKekuArRm/i\nC0440oUVEwvsQK6R5ZIg6q93STaN56u2/Rb2OG82++uF/GIkHGx/9vNqyQMyCjgH\noi3laVlRbciWGc05Fpi2Y5TIDyhesWOV6f8w4Qu3+SCDrTnUqO9eby7ud4s3Z2u6\nHAl1dGVkWVoeyzCE26X+6mdGwPhKBJm7+tdB/m57yCIeDi2Cxc1Sa+3v+X4EUi9T\nwFxa2RfvpiBtMFVJaAvYvQIDAQABo1MwUTAfBgNVHSMEGDAWgBT9kKfvXM+se/M5\nu1YtiYlKBo+wRjAdBgNVHQ4EFgQU/ZCn71zPrHvzObtWLYmJSgaPsEYwDwYDVR0T\nBAgwBgEB/wIBATANBgkqhkiG9w0BAQsFAAOCAQEAeB3LeKbd1gLOk8N6VTf5kxVu\nXjEtg7jQqy+hhln8YtXfWTMYINGjHjnFEQWjRP3C76h2ySyBRv/3mYkb87A0swtH\nnKGZUqwPxc8gbaBPWgbGYQjK60IsQ5wTlRuZ0EsrDPg63PVKryZO6i9YkKZLM2Nz\nYA0nE1gGthnIet5ytGeF0oT5hL7e/tH04IbR0gBGDeFW+JqzFKLFbMYw5UXMutND\nUiwAIIEQDRL9w3hhosgjyTkuR9pi7AaGuwgwByEcHNZ+cEAG4YobCnyAjnDxsNj5\nfKjMAMQmDUa9BU0hEBuBnwKiYa+f0AOO2Vn8KnV16JmnK9D5hSx2QZ6f3Howjw==\n-----END CERTIFICATE-----\n'
    ca0_crt = x509.CRT.from_PEM(pem)


    # the trust store just consists in the root certificate ca0_crt
    trust_store = tls.TrustStore()
    trust_store.add(ca0_crt)
    print(ca0_crt)

    #client
    dtls_cli_ctx = tls.ClientContext(tls.DTLSConfiguration(
        trust_store = trust_store,
        validate_certificates = True,
        ))
    dtls_cli = dtls_cli_ctx.wrap_socket(
        socket.socket(socket.AF_INET, socket.SOCK_DGRAM),
        server_hostname=None,
        )

    port = 4443
    dtls_cli.connect(("127.0.0.1", port))
    block(dtls_cli.do_handshake)
    DATAGRAM = b"hello datagram"
    block(dtls_cli.send, DATAGRAM)
    data = block(dtls_cli.recv, 4096)
    print(data)
