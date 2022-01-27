#ifndef  INCLUDE_SERVER_HH_
#define INCLUDE_SERVER_HH_

#include "socket.hh"

class Server {
 private:
    SocketAcceptor const& _acceptor;

 public:
    explicit Server(SocketAcceptor const& acceptor);
    void run_linear() const;
    void run_fork() const;
    void run_thread_pool(const int num_threads) const;
    void run_thread() const;


    void handle(const Socket_t& sock) const;
};

#endif  // INCLUDE_SERVER_HH_
