/**
 * This file contains the primary logic for your server. It is responsible for
 * handling socket communication - parsing HTTP requests and sending HTTP responses
 * to the client. 
 */
#include <stdio.h>
#include <sys/types.h>
#include <sys/stat.h>
#include <unistd.h>
#include <string.h>
#include <sys/wait.h>
#include <signal.h>
#include <pthread.h>
#include <errno.h>
#include <stdlib.h>
#include <link.h>
#include <dlfcn.h>
#include <sys/time.h>
#include <sys/ipc.h>
#include <sys/shm.h>
#include <fcntl.h>

#include <functional>
#include <iostream>
#include <sstream>
#include <vector>
#include <tuple>
#include <thread>
#include <fstream>

#include "socket.hh"
#include "server.hh"
#include "http_messages.hh"
#include "errors.hh"
#include "misc.hh"
#include "routes.hh"

typedef void (*httprunfunc)(int ssock, const char* querystring);

struct timeval server_start;

double fastest_request = 999999;

double slowest_request = -1;

int num_requests;

extern int porty_boy;

std::vector<std::string> log;

std::string slowest_url;

std::string fastest_url;

pthread_mutex_t mutex;

Server::Server(SocketAcceptor const& acceptor) : _acceptor(acceptor) { }

void Server::run_linear() const {
  while (1) {
    Socket_t sock = _acceptor.accept_connection();
    handle(sock);
    pthread_mutex_lock(&mutex);
    num_requests += 1;
    pthread_mutex_unlock(&mutex);
  }
}

extern "C" void child_terminator(int sig) {
  while (waitpid(-1, NULL, WNOHANG) > 0) {}
}

void Server::run_fork() const {
  struct sigaction sig;
  sig.sa_handler = child_terminator;
  sigemptyset(&sig.sa_mask);
  sig.sa_flags = SA_RESTART;
  sigaction(SIGCHLD, &sig, NULL);

  while (1) {
    Socket_t sock = _acceptor.accept_connection();
    int ret = fork();
    if ( ret == 0 ) {
      signal(SIGCHLD, SIG_DFL);
      handle(sock);
      exit(0);
    } else {
      // signal(SIGCHLD, SIG_IGN);
      waitpid(ret, NULL, WNOHANG);
      pthread_mutex_lock(&mutex);
      num_requests += 1;
      pthread_mutex_unlock(&mutex);
    }
  }
}

struct ThreadParams {
  const Server * server;
  Socket_t sock;
};

void dispatch(ThreadParams * params) {
  params->server->handle(params->sock);
  pthread_mutex_lock(&mutex);
  num_requests += 1;
  pthread_mutex_unlock(&mutex);
  delete params;
}

void Server::run_thread() const {
  while (1) {
    Socket_t sock = _acceptor.accept_connection();
    ThreadParams * threadParams = new ThreadParams;
    threadParams->server = this;
    threadParams->sock = std::move(sock);
    pthread_t thread;
    pthread_attr_t attr;
    pthread_attr_init(&attr);
    pthread_attr_setdetachstate(&attr, PTHREAD_CREATE_DETACHED);
    pthread_create(&thread, &attr, (void* (*)(void*) )dispatch, (void *)  threadParams);
  }
}

struct PoolParam {
  const Server * server;
};

void runner(PoolParam *para) {
  para->server->run_linear();
  delete para;
}

void Server::run_thread_pool(const int num_threads) const {
  pthread_t thread_array[num_threads];
  for ( int i = 0; i < num_threads; i++ ) {
    PoolParam *poolparam = new PoolParam;
    poolparam->server = this;
    pthread_create(&thread_array[i], NULL, (void * (*)(void*) )runner, poolparam);
  }
  pthread_join(thread_array[0], NULL);
}

void parse_request(const Socket_t& sock, HttpRequest* const request) {
  std::string line = sock->readline();
  if ( line.find("GET") == -1 && line.find("POST") == -1 ) {
    request->method = "NULL";
    request->request_uri = "NULL";
    request->http_version = "NULL";
    return;
  }
  request->method = line.substr(0, line.find(' '));
  line = line.substr(line.find(' '));
  line.erase(line.begin());
  request->request_uri = line.substr(0, line.find(' '));
  line = line.substr(line.find(' '));
  line.erase(line.begin());
  request->http_version = line.substr(0, line.find("\r\n"));
  line = sock->readline();
  while ( line.size() > 2 ) {
    std::string key = line.substr(0, line.find(":"));
    line = line.substr(line.find(":"));
    line.erase(line.begin());
    request->headers[key] = line;
    line = sock->readline();
  }
}


void Server::handle(const Socket_t& sock) const {
  struct timeval process_start;
  struct timeval process_end;
  // pthread_mutex_lock(&mutex);
  // num_requests++;
  // pthread_mutex_unlock(&mutex);
  HttpRequest request;
  parse_request(sock, &request);
  HttpResponse response;
  gettimeofday(&process_start, NULL);
  if (request.request_uri.find("/cgi-bin/") != -1) {
    int tempin = dup(0);
    int tempout = dup(1);
    response.http_version = request.http_version;
    response.headers = request.headers;
    if (request.headers.find("Authorization") == request.headers.end()) {
      response.message_body = "ERROR: Failed Authorization";
      response.status_code = 401;
      response.reason_phrase = "NULL";
      pthread_mutex_lock(&mutex);
      log.push_back("IP: " + sock->get_ip() + " route: " + request.request_uri +
                    " response code: " + std::to_string(response.status_code));
      pthread_mutex_unlock(&mutex);
      gettimeofday(&process_end, NULL);
      double process_time = process_end.tv_sec + process_end.tv_usec / 1e6 -
                            process_start.tv_sec + process_start.tv_usec / 1e6;
      if (process_time < fastest_request) {
        pthread_mutex_lock(&mutex);
        fastest_request = process_time;
        fastest_url = sock->get_type() + "data.cs.purdue.edu:" +
                      std::to_string(porty_boy) + request.request_uri;
        pthread_mutex_unlock(&mutex);
      }
      if (process_time > slowest_request) {
        pthread_mutex_lock(&mutex);
        slowest_request = process_time;
        slowest_url = sock->get_type() + "data.cs.purdue.edu:" +
                      std::to_string(porty_boy) + request.request_uri;
        pthread_mutex_unlock(&mutex);
      }
      sock->write(response.to_string());
      return;
    }
    std::string pw_check = request.headers.at("Authorization");
    pw_check = pw_check.substr(pw_check.rfind(' '));
    pw_check.erase(pw_check.begin());
    pw_check = pw_check.substr(0, pw_check.find("\r\n"));
    std::ifstream pw_file("authorized_users_in_b64.txt");
    std::ostringstream pw_stream;
    pw_stream << pw_file.rdbuf();
    std::string pw_valid = pw_stream.str();
    if ( pw_valid.find(pw_check) == -1 ) {
      response.message_body = "ERROR: Failed Authroization";
      response.status_code = 401;
      response.reason_phrase = "NULL";
      pthread_mutex_lock(&mutex);
      log.push_back("IP: " + sock->get_ip() + " route: " + request.request_uri +
                    " response code: " + std::to_string(response.status_code));
      pthread_mutex_unlock(&mutex);
      gettimeofday(&process_end, NULL);
      double process_time = process_end.tv_sec + process_end.tv_usec / 1e6 -
                            process_start.tv_sec + process_start.tv_usec / 1e6;
      if (process_time < fastest_request) {
        pthread_mutex_lock(&mutex);
        fastest_request = process_time;
        fastest_url = sock->get_type() + "data.cs.purdue.edu:" +
                      std::to_string(porty_boy) + request.request_uri;
        pthread_mutex_unlock(&mutex);
      }
      if (process_time > slowest_request) {
        pthread_mutex_lock(&mutex);
        slowest_request = process_time;
        slowest_url = sock->get_type() + "data.cs.purdue.edu:" +
                      std::to_string(porty_boy) + request.request_uri;
        pthread_mutex_unlock(&mutex);
      }
      sock->write(response.to_string());
      return;
    }
    if ( request.request_uri.find(".so") != -1 ) {
      int fdpipe[2];
      pipe(fdpipe);
      int ret = fork();
      if (ret == 0) {
      close(fdpipe[0]);
      std::string args(request.request_uri);
      if (args.find("?") == -1) {
        setenv("QUERY_STRING", "", 1);
        request.query = "";
        setenv("REQUEST_METHOD", "GET", 1);
      } else {
        args = args.substr(args.find("?"));
        args.erase(args.begin());
        setenv("QUERY_STRING", args.c_str(), 1);
        request.query = args;
        setenv("REQUEST_METHOD", "GET", 1);
      }
      std::string exec_rel(request.request_uri);
      std::string exec_real("/homes/jacks668/cs252/lab5-src/http-root-dir");
      if (exec_rel.find("?") != -1) {
        exec_rel = exec_rel.substr(0, exec_rel.find("?"));
      }
      exec_real = exec_real + exec_rel;
      void * lib = dlopen(exec_real.c_str(), RTLD_LAZY);
      if (lib == NULL) {
        response.message_body = "ERROR: dl File Missing";
        response.status_code = 404;
        response.reason_phrase = "NULL";
        pthread_mutex_lock(&mutex);
        log.push_back("IP: " + sock->get_ip() + " route: " +
                      request.request_uri + " response code: " +
                      std::to_string(response.status_code));
        pthread_mutex_unlock(&mutex);
        double process_time = process_end.tv_sec + process_end.tv_usec / 1e6 -
                              process_start.tv_sec +
                              process_start.tv_usec / 1e6;
        if (process_time < fastest_request) {
          pthread_mutex_lock(&mutex);
          fastest_request = process_time;
          fastest_url = sock->get_type() + "data.cs.purdue.edu:" +
                        std::to_string(porty_boy) + request.request_uri;
          pthread_mutex_unlock(&mutex);
        }
        if (process_time > slowest_request) {
          pthread_mutex_lock(&mutex);
          slowest_request = process_time;
          slowest_url = sock->get_type() + "data.cs.purdue.edu:" +
                        std::to_string(porty_boy) + request.request_uri;
          pthread_mutex_unlock(&mutex);
        }
        sock->write(response.to_string());
        return;
      }
      httprunfunc so_run;
      so_run = (httprunfunc) dlsym(lib, "_Z7httpruniPc");
      if (so_run == NULL) {
        response.message_body = "ERROR: htpprun Missing";
        response.status_code = 404;
        response.reason_phrase = "httprun missing";
        pthread_mutex_lock(&mutex);
        log.push_back("IP: " + sock->get_ip() + " route: " + request.request_uri +
                      " response code: " + std::to_string(response.status_code));
        pthread_mutex_unlock(&mutex);
        gettimeofday(&process_end, NULL);
        double process_time = process_end.tv_sec + process_end.tv_usec / 1e6 -
                              process_start.tv_sec + process_start.tv_usec / 1e6;
        if (process_time < fastest_request) {
          pthread_mutex_lock(&mutex);
          fastest_request = process_time;
          fastest_url = sock->get_type() + "data.cs.purdue.edu:" +
                        std::to_string(porty_boy) + request.request_uri;
          pthread_mutex_unlock(&mutex);
        }
        if (process_time > slowest_request) {
          pthread_mutex_lock(&mutex);
          slowest_request = process_time;
          slowest_url = sock->get_type() + "data.cs.purdue.edu:" +
                        std::to_string(porty_boy) + request.request_uri;
          pthread_mutex_unlock(&mutex);
        }
        sock->write(response.to_string());
        return;
      }
      so_run(fdpipe[1], request.query.c_str());
      close(fdpipe[1]);
      } else {
      close(fdpipe[1]);
      waitpid(ret, NULL, 0);
      std::string response_bod("");
      char c;
      while (read(fdpipe[0], &c, 1) > 0) {
        printf("%c", c);
        response_bod.push_back(c);
      }
      response.status_code = 200;
      pthread_mutex_lock(&mutex);
      log.push_back("IP: " + sock->get_ip() + " route: " + request.request_uri +
                    " response code: " + std::to_string(response.status_code));
      pthread_mutex_unlock(&mutex);
      gettimeofday(&process_end, NULL);
      double process_time = process_end.tv_sec + process_end.tv_usec / 1e6 -
                            process_start.tv_sec + process_start.tv_usec / 1e6;
      if (process_time < fastest_request) {
        pthread_mutex_lock(&mutex);
        fastest_request = process_time;
        fastest_url = sock->get_type() + "data.cs.purdue.edu:" +
                      std::to_string(porty_boy) + request.request_uri;
        pthread_mutex_unlock(&mutex);
      }
      if (process_time > slowest_request) {
        pthread_mutex_lock(&mutex);
        slowest_request = process_time;
        slowest_url = sock->get_type() + "data.cs.purdue.edu:" +
                      std::to_string(porty_boy) + request.request_uri;
        pthread_mutex_unlock(&mutex);
      }
      sock->write("HTTP/1.1 200 OK");
      sock->write(response_bod);
      close(fdpipe[0]);
      dup2(tempin, 0);
      close(tempin);
      dup2(tempout, 1);
      close(tempout);
      return;
      }
    }
    int fdpipe[2];
    pipe(fdpipe);
    dup2(fdpipe[1], 1);
    close(fdpipe[1]);
    int ret = fork();
    if ( ret == 0 ) {
      close(fdpipe[0]);
      std::string args(request.request_uri);
      if (args.find("?") == -1) {
        setenv("QUERY_STRING", "", 1);
        request.query = "";
        setenv("REQUEST_METHOD", "GET", 1);
      } else {
        args = args.substr(args.find("?"));
        args.erase(args.begin());
        setenv("QUERY_STRING", args.c_str(), 1);
        request.query = args;
        setenv("REQUEST_METHOD", "GET", 1);
      }
      std::string exec_real("");
      std::string exec_rel(request.request_uri);
      if (exec_rel.find("?") != -1) {
        exec_rel = exec_rel.substr(0, exec_rel.find("?"));
      }
      exec_real = "/homes/jacks668/cs252/lab5-src/http-root-dir" + exec_rel;
      char * arg_array[1];
      arg_array[0] = NULL;
      execvp(exec_real.c_str(), arg_array);
      response.message_body = "ERROR: File Missing";
      response.status_code = 404;
      response.reason_phrase = "NULL";
      pthread_mutex_lock(&mutex);
      log.push_back("IP: " + sock->get_ip() + " route: " + request.request_uri +
                    " response code: " + std::to_string(response.status_code));
      pthread_mutex_unlock(&mutex);
      gettimeofday(&process_end, NULL);
      double process_time = process_end.tv_sec + process_end.tv_usec / 1e6 -
                            process_start.tv_sec + process_start.tv_usec / 1e6;
      if (process_time < fastest_request) {
        pthread_mutex_lock(&mutex);
        fastest_request = process_time;
        fastest_url = sock->get_type() + "data.cs.purdue.edu:" +
                      std::to_string(porty_boy) + request.request_uri;
        pthread_mutex_unlock(&mutex);
      }
      if (process_time > slowest_request) {
        pthread_mutex_lock(&mutex);
        slowest_request = process_time;
        slowest_url = sock->get_type() + "data.cs.purdue.edu:" +
                      std::to_string(porty_boy) + request.request_uri;
        pthread_mutex_unlock(&mutex);
      }
      sock->write(response.to_string());
      return;
    } else {
      waitpid(ret, NULL, 0);
      // dup2(fdpipe[0], 0);
      // close(fdpipe[0]);
      std::string response_bod("");
      dup2(tempout, 1);
      char c;
      while (read(fdpipe[0], &c, 1) > 0) {
        printf("%c", c);
        response_bod.push_back(c);
      }
      response.status_code = 200;
      pthread_mutex_lock(&mutex);
      log.push_back("IP: " + sock->get_ip() + " route: " + request.request_uri +
                    " response code: " + std::to_string(response.status_code));
      pthread_mutex_unlock(&mutex);
      gettimeofday(&process_end, NULL);
      double process_time = process_end.tv_sec + process_end.tv_usec / 1e6 -
                            process_start.tv_sec + process_start.tv_usec / 1e6;
      if (process_time < fastest_request) {
        pthread_mutex_lock(&mutex);
        fastest_request = process_time;
        fastest_url = sock->get_type() + "data.cs.purdue.edu:" +
                      std::to_string(porty_boy) + request.request_uri;
        pthread_mutex_unlock(&mutex);
      }
      if (process_time > slowest_request) {
        pthread_mutex_lock(&mutex);
        slowest_request = process_time;
        slowest_url = sock->get_type() + "data.cs.purdue.edu:" +
                      std::to_string(porty_boy) + request.request_uri;
        pthread_mutex_unlock(&mutex);
      }
      sock->write("HTTP/1.1 200 OK");
      sock->write(response_bod);
      close(fdpipe[0]);
      dup2(tempin, 0);
      close(tempin);
      dup2(tempout, 1);
      close(tempout);
      return;
    }
  } else if (request.request_uri.find("/stats") != -1) {
    response.http_version = request.http_version;
    response.headers = request.headers;
    if (request.headers.find("Authorization") == request.headers.end()) {
      response.message_body = "ERROR: Failed Authorization";
      response.status_code = 401;
      response.reason_phrase = "NULL";
      pthread_mutex_lock(&mutex);
      log.push_back("IP: " + sock->get_ip() + " route: " + request.request_uri +
                    " response code: " + std::to_string(response.status_code));
      pthread_mutex_unlock(&mutex);
      gettimeofday(&process_end, NULL);
      double process_time = process_end.tv_sec + process_end.tv_usec / 1e6 -
                            process_start.tv_sec + process_start.tv_usec / 1e6;
      if (process_time < fastest_request) {
        pthread_mutex_lock(&mutex);
        fastest_request = process_time;
        fastest_url = sock->get_type() + "data.cs.purdue.edu:" +
                      std::to_string(porty_boy) + request.request_uri;
        pthread_mutex_unlock(&mutex);
      }
      if (process_time > slowest_request) {
        pthread_mutex_lock(&mutex);
        slowest_request = process_time;
        slowest_url = sock->get_type() + "data.cs.purdue.edu:" +
                      std::to_string(porty_boy) + request.request_uri;
        pthread_mutex_unlock(&mutex);
      }
      sock->write(response.to_string());
      return;
    }
    std::string pw_check = request.headers.at("Authorization");
    pw_check = pw_check.substr(pw_check.rfind(' '));
    pw_check.erase(pw_check.begin());
    pw_check = pw_check.substr(0, pw_check.find("\r\n"));
    std::ifstream pw_file("authorized_users_in_b64.txt");
    std::ostringstream pw_stream;
    pw_stream << pw_file.rdbuf();
    std::string pw_valid = pw_stream.str();
    if ( pw_valid.find(pw_check) == -1 ) {
      response.message_body = "ERROR: Failed Authroization";
      response.status_code = 401;
      response.reason_phrase = "NULL";
      pthread_mutex_lock(&mutex);
      log.push_back("IP: " + sock->get_ip() + " route: " + request.request_uri +
                    " response code: " + std::to_string(response.status_code));
      pthread_mutex_unlock(&mutex);
      gettimeofday(&process_end, NULL);
      double process_time = process_end.tv_sec + process_end.tv_usec / 1e6 -
                            process_start.tv_sec + process_start.tv_usec / 1e6;
      if (process_time < fastest_request) {
        pthread_mutex_lock(&mutex);
        fastest_request = process_time;
        fastest_url = sock->get_type() + "data.cs.purdue.edu:" +
                      std::to_string(porty_boy) + request.request_uri;
        pthread_mutex_unlock(&mutex);
      }
      if (process_time > slowest_request) {
        pthread_mutex_lock(&mutex);
        slowest_request = process_time;
        slowest_url = sock->get_type() + "data.cs.purdue.edu:" +
                      std::to_string(porty_boy) + request.request_uri;
        pthread_mutex_unlock(&mutex);
      }
      sock->write(response.to_string());
      return;
    }
    response.reason_phrase = "text/plain";
    response.status_code = 200;
    pthread_mutex_lock(&mutex);
    log.push_back("IP: " + sock->get_ip() + " route: " + request.request_uri +
                  " response code: " + std::to_string(response.status_code));
    pthread_mutex_unlock(&mutex);
    gettimeofday(&process_end, NULL);
    double server_uptime = process_end.tv_sec + process_end.tv_usec / 1e6 -
                           server_start.tv_sec + server_start.tv_usec / 1e6;
    double process_time = process_end.tv_sec + process_end.tv_usec / 1e6 -
                          process_start.tv_sec + process_start.tv_usec / 1e6;
    if (process_time < fastest_request) {
      pthread_mutex_lock(&mutex);
      fastest_request = process_time;
      fastest_url = sock->get_type() + "data.cs.purdue.edu:" +
                    std::to_string(porty_boy) + request.request_uri;
      pthread_mutex_unlock(&mutex);
    }
    if (process_time > slowest_request) {
      pthread_mutex_lock(&mutex);
      slowest_request = process_time;
      slowest_url = sock->get_type() + "data.cs.purdue.edu:" +
                    std::to_string(porty_boy) + request.request_uri;
      pthread_mutex_unlock(&mutex);
    }
    response.message_body = "David Jackson, jacks668\r\n";
    response.message_body = response.message_body + "Server Uptime: " +
                            std::to_string(server_uptime) + " seconds\r\n";
    response.message_body += "Num_requests: " + std::to_string(num_requests) +
                             "\r\n";
    response.message_body += "Max Service Time: " +
                             std::to_string(slowest_request) + " seconds " +
                             "from: " + slowest_url + "\r\n";
    response.message_body += "Min Service Time: " +
                             std::to_string(fastest_request) + " seconds " +
                             "from: " + fastest_url + "\r\n";
    sock->write(response.to_string());
    return;
  } else if (request.request_uri.find("/logs") != -1) {
    response.http_version = request.http_version;
    response.headers = request.headers;
    if (request.headers.find("Authorization") == request.headers.end()) {
      response.message_body = "ERROR: Failed Authorization";
      response.status_code = 401;
      response.reason_phrase = "NULL";
      pthread_mutex_lock(&mutex);
      log.push_back("IP: " + sock->get_ip() + " route: " + request.request_uri +
                    " response code: " + std::to_string(response.status_code));
      pthread_mutex_unlock(&mutex);
      gettimeofday(&process_end, NULL);
      double process_time = process_end.tv_sec + process_end.tv_usec / 1e6 -
                            process_start.tv_sec + process_start.tv_usec / 1e6;
      if (process_time < fastest_request) {
        pthread_mutex_lock(&mutex);
        fastest_request = process_time;
        fastest_url = sock->get_type() + "data.cs.purdue.edu:" +
                      std::to_string(porty_boy) + request.request_uri;
        pthread_mutex_unlock(&mutex);
      }
      if (process_time > slowest_request) {
        pthread_mutex_lock(&mutex);
        slowest_request = process_time;
        slowest_url = sock->get_type() + "data.cs.purdue.edu:" +
                      std::to_string(porty_boy) + request.request_uri;
        pthread_mutex_unlock(&mutex);
      }
      sock->write(response.to_string());
      return;
    }
    std::string pw_check = request.headers.at("Authorization");
    pw_check = pw_check.substr(pw_check.rfind(' '));
    pw_check.erase(pw_check.begin());
    pw_check = pw_check.substr(0, pw_check.find("\r\n"));
    std::ifstream pw_file("authorized_users_in_b64.txt");
    std::ostringstream pw_stream;
    pw_stream << pw_file.rdbuf();
    std::string pw_valid = pw_stream.str();
    if ( pw_valid.find(pw_check) == -1 ) {
      response.message_body = "ERROR: Failed Authroization";
      response.status_code = 401;
      response.reason_phrase = "NULL";
      pthread_mutex_lock(&mutex);
      log.push_back("IP: " + sock->get_ip() + " route: " + request.request_uri +
                    " response code: " + std::to_string(response.status_code));
      pthread_mutex_unlock(&mutex);
      gettimeofday(&process_end, NULL);
      double process_time = process_end.tv_sec + process_end.tv_usec / 1e6 -
                            process_start.tv_sec + process_start.tv_usec / 1e6;
      if (process_time < fastest_request) {
        pthread_mutex_lock(&mutex);
        fastest_request = process_time;
        fastest_url = sock->get_type() + "data.cs.purdue.edu:" +
                      std::to_string(porty_boy) + request.request_uri;
        pthread_mutex_unlock(&mutex);
      }
      if (process_time > slowest_request) {
        pthread_mutex_lock(&mutex);
        slowest_request = process_time;
        slowest_url = sock->get_type() + "data.cs.purdue.edu:" +
                      std::to_string(porty_boy) + request.request_uri;
        pthread_mutex_unlock(&mutex);
      }
      sock->write(response.to_string());
      return;
    }
    response.status_code = 200;
    response.reason_phrase = "text/plain";
    response.message_body = "Request Log\r\n";
    pthread_mutex_lock(&mutex);
    log.push_back("IP: " + sock->get_ip() + " route: " + request.request_uri +
                  " response code: " + std::to_string(response.status_code));
    pthread_mutex_unlock(&mutex);
    pthread_mutex_lock(&mutex);
    for (int i = 0; i < log.size(); i++) {
      response.message_body += log.at(i) + "\r\n";
    }
    pthread_mutex_unlock(&mutex);
    gettimeofday(&process_end, NULL);
    double process_time = process_end.tv_sec + process_end.tv_usec / 1e6 -
                          process_start.tv_sec + process_start.tv_usec / 1e6;
    if (process_time < fastest_request) {
      pthread_mutex_lock(&mutex);
      fastest_request = process_time;
      fastest_url = sock->get_type() + "data.cs.purdue.edu:" +
                    std::to_string(porty_boy) + request.request_uri;
      pthread_mutex_unlock(&mutex);
    }
    if (process_time > slowest_request) {
      pthread_mutex_lock(&mutex);
      slowest_request = process_time;
      slowest_url = sock->get_type() + "data.cs.purdue.edu:" +
                    std::to_string(porty_boy) + request.request_uri;
      pthread_mutex_unlock(&mutex);
    }
    int log_out = open("myhttpd.log", O_WRONLY|O_CREAT|O_TRUNC, 0660);
    dprintf(log_out, "%s", response.message_body.c_str());
    close(log_out);
    sock->write(response.to_string());
    return;
  } else {
    response = handle_htdocs(request);
  }
  if (request.method.find("NULL") != -1) {
    return;
  }
  request.message_body = response.message_body;
  // if ( response.reason_phrase.find("binary") == -1 ) {
    // request.print();
    // std::cout << response.to_string() << std::endl;
  // }
  pthread_mutex_lock(&mutex);
  log.push_back("IP: " + sock->get_ip() + " route: " + request.request_uri +
                " response code: " + std::to_string(response.status_code));
  pthread_mutex_unlock(&mutex);
  gettimeofday(&process_end, NULL);
  double process_time = process_end.tv_sec + process_end.tv_usec / 1e6 -
                        process_start.tv_sec + process_start.tv_usec / 1e6;
  if (process_time < fastest_request) {
    pthread_mutex_lock(&mutex);
    fastest_request = process_time;
    fastest_url = sock->get_type() + "data.cs.purdue.edu:" +
                  std::to_string(porty_boy) + request.request_uri;
    pthread_mutex_unlock(&mutex);
  }
  if (process_time > slowest_request) {
    pthread_mutex_lock(&mutex);
    slowest_request = process_time;
    slowest_url = sock->get_type() + "data.cs.purdue.edu:" +
                  std::to_string(porty_boy) + request.request_uri;
    pthread_mutex_unlock(&mutex);
  }
  sock->write(response.to_string());
}

