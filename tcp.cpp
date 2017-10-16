//
// Created by Xiaoting Tang on 10/16/17.
//

#include <iostream>
#include <netinet/in.h>
#include <arpa/inet.h>
#include <netdb.h>

void buildConnectionAsServer(int port, int& listen_sock, int& peer_sock) {
    int result;
    int opt_val = 1;
    struct sockaddr_in address;

    listen_sock = socket(AF_INET, SOCK_STREAM, 0);

    memset(&address, 0, sizeof(address));

    address.sin_family = AF_INET;
    address.sin_port = htons(port);
    address.sin_addr.s_addr = INADDR_ANY;

    setsockopt(listen_sock, SOL_SOCKET, SO_REUSEADDR, &opt_val, sizeof(opt_val));

    result = bind(listen_sock, (struct sockaddr*)&address, sizeof(address));
    if (result != 0) {
        std::cerr << "bind() failed." << std::endl;
        exit(result);
    }
    result = listen(listen_sock, 5);
    if (result != 0) {
        std::cerr << "listen() failed." << std::endl;
        exit(result);
    }

    // Accept
    size_t size = sizeof(address);
    peer_sock = accept(listen_sock, (struct sockaddr*)&address, (socklen_t *)&size);
    if (peer_sock < 0) {
        std::cerr << "accept() failed." << std::endl;
        exit(peer_sock);
    }

}
void buildConnectionAsClient(std::string ip, int port, int& sock) {
    struct addrinfo* res;
    struct sockaddr_in address;
    address.sin_family = AF_INET;
    address.sin_port = htons(port);

    int result = getaddrinfo(ip.c_str(), NULL, NULL, &res);
    if (result != 0) {
        std::cerr << "Peer hostname invalid." << std::endl;
        exit(-1);
    }
    freeaddrinfo(res);
    inet_pton(AF_INET, ip.c_str(), &(address.sin_addr));
    sock = socket(AF_INET, SOCK_STREAM, 0);
    if (::connect(sock, (struct sockaddr*)&address, sizeof(address)) != 0) {
        std::cerr << "connect() failed." << std::endl;
        exit(-1);
    }
}
