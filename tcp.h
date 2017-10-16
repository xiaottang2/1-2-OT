#include <string>

void buildConnectionAsServer(int port, int& listen_sock, int& peer_sock);
void buildConnectionAsClient(std::string ip, int port, int& sock);