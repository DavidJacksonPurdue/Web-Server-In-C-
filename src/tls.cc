/**
 * This file contains your implementation of a TLS socket and socket acceptor. The TLS socket uses
 * the OpenSSL library to handle all socket communication, so you need to configure OpenSSL and use the
 * OpenSSL functions to read/write to the socket. src/tcp.cc is provided for your reference on 
 * Sockets and SocketAdaptors and examples/simple_tls_server.c is provided for your reference on OpenSSL.
 */

#include <errno.h>
#include <unistd.h>
#include <sys/types.h>
#include <sys/socket.h>
#include <arpa/inet.h>
#include <openssl/ssl.h>
#include <openssl/err.h>

#include <iostream>
#include <sstream>
#include <cstring>
#include <memory>

#include "tls.hh"
#include "errors.hh"

std::string ip1("");

TLSSocket::TLSSocket(int port_no, struct sockaddr_in addr, SSL* ssl) :
  _socket(port_no), _addr(addr), _ssl(ssl) {
    char inet_pres[INET_ADDRSTRLEN];
    if (inet_ntop(addr.sin_family, &(addr.sin_addr), inet_pres, INET_ADDRSTRLEN)) {
      ip1 = inet_pres;
      std::cout << "Received a connection from " << inet_pres << std::endl;
    }
}
TLSSocket::~TLSSocket() noexcept {
    std::cout << "Closing TCP socket fd " << _socket;
    char inet_pres[INET_ADDRSTRLEN];
    if (inet_ntop(_addr.sin_family, &(_addr.sin_addr), inet_pres, INET_ADDRSTRLEN)) {
      std::cout << " from " << inet_pres;
    }
    std::cout << std::endl;
    SSL_free(_ssl);
    close(_socket);
}

std::string TLSSocket::get_ip() {
    return ip1;
}

std::string TLSSocket::get_type() {
    return "https://";
}

int TLSSocket::get_socket() {
    return _socket;
}

char TLSSocket::getc() {
    char c;
    int read = SSL_read(_ssl, &c, 1);
    if (read < 1) {
      c = EOF;
    } else if (read > 1) {
      throw ConnectionError("Read more than one byte when expecting to only read one.");
    }
    return c;
}

ssize_t TLSSocket::read(char *buf, size_t buf_len) {
    ssize_t r = recv(_socket, buf, buf_len, 0);
    if (r == -1) {
      throw ConnectionError("Unable to read a character: " + std::string(strerror(errno)));
    }
    return r;
}

std::string TLSSocket::readline() {
    std::string str;
    char c;
    while ((c = getc()) != '\n' && c != EOF) {
        str.append(1, c);
    }
    if (c == '\n') {
        str.append(1, '\n');
    }
    return str;
}

void TLSSocket::write(std::string const &str) {
    write(str.c_str(), str.length());
}

void TLSSocket::write(char const *const buf, const size_t buf_len) {
    if (buf == NULL)
        return;
  int ret_code = SSL_write(_ssl, buf, buf_len);
  if (ret_code == -1) {
    throw ConnectionError("Unable to write: " + std::string(strerror(errno)));
  } else if ((size_t)ret_code != buf_len) {
    size_t i;
    std::stringstream buf_hex_stream;
    for (i = 0; i < buf_len; i++) {
      buf_hex_stream << std::hex << buf[i];
    }
    throw ConnectionError("Could not write all bytes of: \'" + buf_hex_stream.str() +
        "\'. Expected " + std::to_string(buf_len) + " but actually sent " +
        std::to_string(ret_code));
  }
}

TLSSocketAcceptor::TLSSocketAcceptor(const int portno) {
  _addr.sin_family = AF_INET;
  _addr.sin_port = htons(portno);
  _addr.sin_addr.s_addr = htonl(INADDR_ANY);

  SSL_load_error_strings();
  OpenSSL_add_ssl_algorithms();

  const SSL_METHOD *method;

  method = SSLv23_server_method();

  _ssl_ctx = SSL_CTX_new(method);
  if (!_ssl_ctx) {
    throw ConnectionError("Unable to create ctx: " + std::string(strerror(errno)));
  }

  SSL_CTX_set_ecdh_auto(_ssl_ctx, 1);
  if (SSL_CTX_use_certificate_file(_ssl_ctx, "cert.pem", SSL_FILETYPE_PEM) <= 0) {
    throw ConnectionError("Unable to loacte cert.pem: " + std::string(strerror(errno)));
  }
  if (SSL_CTX_use_PrivateKey_file(_ssl_ctx, "key.pem", SSL_FILETYPE_PEM) <= 0) {
    throw ConnectionError("Unable to locate key.pem: " + std::string(strerror(errno)));
  }
  _master_socket = socket(AF_INET, SOCK_STREAM, 0);
  if (_master_socket < 0) {
    throw ConnectionError("Unable to create socket: " + std::string(strerror(errno)));
  }

  int optval = 1;
  if (setsockopt(_master_socket, SOL_SOCKET, SO_REUSEADDR, &optval, sizeof(optval)) < 0) {
    throw ConnectionError("Unable to set socket options: " + std::string(strerror(errno)));
  }
  if (bind(_master_socket, (struct sockaddr*)&_addr, sizeof(_addr)) < 0) {
    throw ConnectionError("Unable to bind to socket: " + std::string(strerror(errno)));
  }
  if (listen(_master_socket, 50) < 0) {
    throw ConnectionError("Unable to listen to socket: " + std::string(strerror(errno)));
  }
}

Socket_t TLSSocketAcceptor::accept_connection() const {
  struct sockaddr_in addr;
  socklen_t addr_len = sizeof(addr);
  int client = accept(_master_socket, (struct sockaddr*)&addr, &addr_len);
  if (client == -1) {
    throw ConnectionError("Unable to accept connection: " + std::string(strerror(errno)));
  }
  SSL *ssl;
  ssl = SSL_new(_ssl_ctx);
  SSL_set_fd(ssl, client);
  if (SSL_accept(ssl) <= 0) {
    ERR_print_errors_fp(stderr);
  }
  return std::make_unique<TLSSocket>(client, addr, ssl);
}

TLSSocketAcceptor::~TLSSocketAcceptor() noexcept {
  std::cout<< "Closing socket " << _master_socket << std::endl;
  close(_master_socket);
  SSL_CTX_free(_ssl_ctx);
  EVP_cleanup();
}
