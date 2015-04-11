/*
 * E_TCPAssignment.cpp
 *
 *  Created on: 2014. 11. 20.
 *      Author: 근홍
 */


#include <E/E_Common.hpp>
#include <E/Networking/E_Host.hpp>
#include <E/Networking/E_Networking.hpp>
#include <cerrno>
#include <E/Networking/E_Packet.hpp>
#include <E/Networking/E_NetworkUtil.hpp>
#include "TCPAssignment.hpp"

namespace E
{

TCPAssignment::TCPAssignment(Host* host) : HostModule("TCP", host),
		NetworkModule(this->getHostModuleName(), host->getNetworkSystem()),
		SystemCallInterface(AF_INET, IPPROTO_TCP, host),
		NetworkLog(host->getNetworkSystem()),
		TimerModule(host->getSystem())
{

}

TCPAssignment::~TCPAssignment()
{

}

void TCPAssignment::initialize()
{

}

void TCPAssignment::finalize()
{

}

void TCPAssignment::systemCallback(UUID syscallUUID, int pid, const SystemCallParameter& param)
{
	switch(param.syscallNumber)
	{
	case SOCKET:
		this->syscall_socket(syscallUUID, pid, param.param1_int, param.param2_int);
		break;
	case CLOSE:
		this->syscall_close(syscallUUID, pid, param.param1_int);
		break;
	case READ:
		//this->syscall_read(syscallUUID, pid, param.param1_int, param.param2_ptr, param.param3_int);
		break;
	case WRITE:
		//this->syscall_write(syscallUUID, pid, param.param1_int, param.param2_ptr, param.param3_int);
		break;
	case CONNECT:
		//this->syscall_connect(syscallUUID, pid, param.param1_int,
		//		static_cast<struct sockaddr*>(param.param2_ptr), (socklen_t)param.param3_int);
		break;
	case LISTEN:
		//this->syscall_listen(syscallUUID, pid, param.param1_int, param.param2_int);
		break;
	case ACCEPT:
		//this->syscall_accept(syscallUUID, pid, param.param1_int,
		//		static_cast<struct sockaddr*>(param.param2_ptr),
		//		static_cast<socklen_t*>(param.param3_ptr));
		break;
	case BIND:
		this->syscall_bind(syscallUUID, pid, param.param1_int,
				static_cast<struct sockaddr *>(param.param2_ptr),
				(socklen_t) param.param3_int);
		break;
	case GETSOCKNAME:
		this->syscall_getsockname(syscallUUID, pid, param.param1_int,
				static_cast<struct sockaddr *>(param.param2_ptr),
				static_cast<socklen_t*>(param.param3_ptr));
		break;
	case GETPEERNAME:
		//this->syscall_getpeername(syscallUUID, pid, param.param1_int,
		//		static_cast<struct sockaddr *>(param.param2_ptr),
		//		static_cast<socklen_t*>(param.param3_ptr));
		break;
	default:
		assert(0);
	}
}
void TCPAssignment::syscall_socket(UUID syscallUUID,int pid, int param1, int param2)
{
	int sock_fd;
	sock_fd=this->createFileDescriptor(pid);
	this->returnSystemCall(syscallUUID,sock_fd);
}
void TCPAssignment::syscall_close(UUID syscallUUID, int pid, int param1)
{
        std::list<struct b_sock>::iterator it;
        it = this->find_b_sock_by(param1);
        if (it!=this->b_sock_map.end())
            this->b_sock_map.erase(it);
	this->removeFileDescriptor(pid,param1);
	this->returnSystemCall(syscallUUID,0);
}
void TCPAssignment::syscall_bind(UUID syscallUUID, int pid, int param1_int, sockaddr * param2_ptr, socklen_t param3_int)
{
        b_sock new_sock;

        struct sockaddr_in* sock_info = (sockaddr_in *)param2_ptr;
        new_sock.fd = param1_int;
        new_sock.addr = sock_info->sin_addr.s_addr;
        new_sock.port = sock_info->sin_port;


        if (this->is_overlap(new_sock)){
            this->returnSystemCall(syscallUUID,1);
        } else {
            this->b_sock_map.push_back(new_sock);
            this->returnSystemCall(syscallUUID,0);
        }
        

}

bool TCPAssignment::is_overlap(b_sock new_sock)
{
    std::list<struct b_sock> b_sock_map = this->b_sock_map;
    std::list<struct b_sock>::iterator it ;

    for(it=b_sock_map.begin(); it != b_sock_map.end(); ++it){
        bool check_fd = ((*it).fd == new_sock.fd);
        bool check_sp_ip = ((*it).addr == 0 || new_sock.addr == 0);
        bool check_ip_port = ((check_sp_ip || ((*it).addr == new_sock.addr)) && (*it).port == new_sock.port);
        if(check_fd || check_ip_port)
            return true;
    }
    return false;
}

std::list<struct b_sock>::iterator TCPAssignment::find_b_sock_by(int fd)
{
    std::list<struct b_sock> b_sock_map = this->b_sock_map;
    std::list<struct b_sock>::iterator it ;

    for(it=this->b_sock_map.begin(); it != this->b_sock_map.end(); ++it){
        if ((*it).fd==fd){
            return it;
        }
    }
    return this->b_sock_map.end();
}

void TCPAssignment::syscall_getsockname(UUID syscallUUID, int pid, int fd, struct sockaddr * sock_addr, socklen_t* sock_len)
{
    std::list<struct b_sock>::iterator it = this->find_b_sock_by(fd);
    
    ((struct sockaddr_in*)sock_addr)->sin_family = AF_INET;
    ((struct sockaddr_in*)sock_addr)->sin_addr.s_addr = (*it).addr;
    ((struct sockaddr_in*)sock_addr)->sin_port = (*it).port;
    this->returnSystemCall(syscallUUID, 0);
}

void TCPAssignment::packetArrived(std::string fromModule, Packet* packet)
{

}

void TCPAssignment::timerCallback(void* payload)
{

}

}
