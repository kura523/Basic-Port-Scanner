#ifndef SENDER_H
#define SENDER_H

// 暴露给外部调用的发包接口
void send_syn_packet(int sock, const char* ip, int port);
void send_udp_packet(int sock, const char* ip, int port);

#endif
