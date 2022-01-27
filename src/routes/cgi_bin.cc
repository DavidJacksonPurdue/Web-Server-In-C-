#include <errno.h>
#include <stdlib.h>
#include <stdio.h>
#include <unistd.h>
#include <sys/types.h>
#include <sys/wait.h>

#include <iostream>
#include <fstream>
#include <string>

#include "http_messages.hh"

// You could implement your logic for handling /cgi-bin requests here

HttpResponse handle_cgi_bin(const HttpRequest& request) {
  int tempin = dup(0);
  int tempout = dup(1);
  HttpResponse resp;
  resp.http_version = request.http_version;
  resp.headers = request.headers;
  if (request.headers.find("Authorization") == request.headers.end()) {
    resp.message_body = "ERROR: Failed Authorization";
    resp.status_code = 401;
    resp.reason_phrase = "NULL";
    return resp;
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
    resp.message_body = "ERROR: Failed Authroization";
    resp.status_code = 401;
    resp.reason_phrase = "NULL";
    return resp;
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
      setenv("REQUEST_METHOD", "GET", 1);
    } else {
      args = args.substr(args.find("?"));
      args.erase(args.begin());
      setenv("QUERY_STRING", args.c_str(), 1);
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
    resp.message_body = "ERROR: File Missing";
    resp.status_code = 404;
    resp.reason_phrase = "NULL";
    return resp;
  } else {
    waitpid(ret, NULL, 0);
    // dup2(fdpipe[0], 0);
    // close(fdpipe[0]);
    std::string response_bod("");
    // dup2(tempout, 1);
    char c;
    while (read(fdpipe[0], &c, 1) > 0) {
      // printf("%c", c);
      response_bod.push_back(c);
    }
    close(fdpipe[0]);
    resp.status_code = 200;
    if (response_bod.find("Content-type: ") != -1) {
      resp.reason_phrase = response_bod.substr(response_bod.find("Content-type: "));
      resp.reason_phrase = resp.reason_phrase.substr(resp.reason_phrase.find(" "));
      resp.reason_phrase.erase(resp.reason_phrase.begin());
    }
    response_bod = response_bod.substr(response_bod.find("\n\n"));
    response_bod.erase(response_bod.begin());
    resp.message_body = response_bod;
    dup2(tempin, 0);
    close(tempin);
    dup2(tempout, 1);
    close(tempout);
    return resp;
  }
}
