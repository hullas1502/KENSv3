/*
 * E_TCPAssignment.hpp
 *
 *  Created on: 2014. 11. 20.
 *      Author: 근홍
 */

#ifndef E_TCPASSIGNMENT_HPP_
#define E_TCPASSIGNMENT_HPP_


#include <E/Networking/E_Networking.hpp>
#include <E/Networking/E_Host.hpp>
#include <arpa/inet.h>
#include <netinet/tcp.h>
#include <netinet/ip.h>
#include <netinet/in.h>
#include <list>


#include <E/E_TimerModule.hpp>

namespace E
{
struct b_sock { 
    int fd;
    long addr;
    short port;
};
//typedef struct b_sock_ b_sock;

class TCPAssignment : public HostModule, public NetworkModule, public SystemCallInterface, private NetworkLog, private TimerModule
{
public:
        std::list<struct b_sock> b_sock_map;
private:
	virtual void timerCallback(void* payload) final;
/* custom declare */
	void syscall_socket(UUID syscall, int pid, int param1, int param2);
	void syscall_close(UUID syscall, int pid, int param1);
        void syscall_bind(UUID syscallUUID, int pid, int param1_int, struct sockaddr * param2_ptr, socklen_t param3_int);
        bool is_overlap(b_sock new_sock);
        std::list<struct b_sock>::iterator find_b_sock_by(int fd);

public:
	TCPAssignment(Host* host);
	virtual void initialize();
	virtual void finalize();
	virtual ~TCPAssignment();
protected:
	virtual void systemCallback(UUID syscallUUID, int pid, const SystemCallParameter& param) final;
	virtual void packetArrived(std::string fromModule, Packet* packet) final;
};

class TCPAssignmentProvider
{
private:
	TCPAssignmentProvider() {}
	~TCPAssignmentProvider() {}
public:
	static HostModule* allocate(Host* host) { return new TCPAssignment(host); }
};

}


#endif /* E_TCPASSIGNMENT_HPP_ */
