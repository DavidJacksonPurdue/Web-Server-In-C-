#include <sys/types.h>
#include <sys/stat.h>
#include <unistd.h>
#include <stdio.h>
#include <string.h>

#include <iostream>
#include <fstream>

#include "http_messages.hh"
#include "misc.hh"

// You may find implementing this function and using it in server.cc helpful

HttpResponse handle_htdocs(const HttpRequest& request) {
  HttpResponse resp;
  resp.http_version = request.http_version;
  resp.headers = request.headers;
  if ( request.headers.find("Authorization") == request.headers.end() ) {
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
  std::string http_file_path("");
  http_file_path = "/homes/jacks668/cs252/lab5-src/http-root-dir/htdocs" + request.request_uri;
  if ( http_file_path.find("..") != -1 ) {
    resp.message_body = "ERROR: File Missing";
    resp.status_code = 404;
    resp.reason_phrase = "NULL";
    return resp;
  }
  FILE *req_file = fopen(http_file_path.c_str(), "r");
  if ( req_file == NULL ) {
    resp.message_body = "ERROR: File Missing";
    resp.status_code = 404;
    resp.reason_phrase = "NULL";
  } else {
    struct stat stats;
    stat(http_file_path.c_str(), &stats);
    if (S_ISDIR(stats.st_mode)) {
      fclose(req_file);
      req_file = NULL;
      http_file_path = http_file_path + "/index.html";
      req_file = fopen(http_file_path.c_str(), "r");
      if ( req_file == NULL ) {
        resp.message_body = "ERROR: File Missing";
        resp.status_code = 404;
        resp.reason_phrase = "NULL";
      } else {
        resp.status_code = 200;
        resp.reason_phrase = get_content_type(http_file_path);
        std::ostringstream object_stream;
        if ( resp.reason_phrase.find("binary") != -1 ) {
          std::ifstream f_in(http_file_path, std::ifstream::binary);
          object_stream << f_in.rdbuf();
          resp.message_body = object_stream.str();
        } else {
          std::ifstream f_in(http_file_path);
          object_stream << f_in.rdbuf();
          resp.message_body = object_stream.str();
        }
        fclose(req_file);
        req_file = NULL;
      }
    } else {
      resp.status_code = 200;
      resp.reason_phrase = get_content_type(http_file_path);
      std::ostringstream object_stream;
      if ( resp.reason_phrase.find("binary") != -1 ) {
        std::ifstream f_in(http_file_path, std::ifstream::binary);
        object_stream << f_in.rdbuf();
        resp.message_body = object_stream.str();
      } else {
        std::ifstream f_in(http_file_path);
        object_stream << f_in.rdbuf();
        resp.message_body = object_stream.str();
      }
      fclose(req_file);
      req_file = NULL;
    }
  }
  return resp;
}
