#include<iostream>
#include<string.h>
#include<stdlib.h>
#include<cstdio>
#include<sys/socket.h>
#include<sys/types.h>
#include<arpa/inet.h>
#include<netinet/in.h>
#include<netdb.h>
#include<unistd.h>
#include<cstdlib>
#include<errno.h>
#include<map>
#include<pthread.h>
#include<poll.h>
#include <fcntl.h>
#include "prefix.cpp"
#include "ip.h"
#include "tcp.h"
#include "ip_icmp.h"
#include "services.h"
#include "udp.h"
#include "find_service_and_version.h"
//#include "checksum_and_selfip.h"
//#include "reference_structures.h"
#include<time.h>
using namespace std;

struct DNS_HEADER
{
        unsigned short id; // identification number
        unsigned char rd :1; // recursion desired
        unsigned char tc :1; // truncated message
        unsigned char aa :1; // authoritive answer
        unsigned char opcode :4; // purpose of message
        unsigned char qr :1; // query/response flag
        unsigned char rcode :4; // response code
        unsigned char cd :1; // checking disabled
        unsigned char ad :1; // authenticated data
        unsigned char z :1; // its z! reserved
        unsigned char ra :1; // recursion available
        unsigned short q_count; // number of question entries
        unsigned short ans_count; // number of answer entries
        unsigned short auth_count; // number of authority entries
        unsigned short add_count;
        unsigned short qtype;
        unsigned short qclass;
        char* qname;
};
int syn_count;
int ack_count;
int fin_count;
int xmas_count;
int null_count;
char syn_set, ack_set, fin_set;
char null_set, xmas_set;
int min_port = 1;
int max_port = 1024;
map<int, string> port_ack_status;
map<int, string> port_syn_status;
map<int, string> port_fin_status;
map<int, string> port_null_status;
map<int, string> port_xmas_status;
map<int, string> port_udp_scan;
time_t timer;
struct tm y2k;
double seconds;
int speedup;
int recieved_jobs;
int deleted_jobs;

pthread_mutex_t mutex1 = PTHREAD_MUTEX_INITIALIZER;
pthread_mutex_t mutex2 = PTHREAD_MUTEX_INITIALIZER;
pthread_mutex_t mutex3 = PTHREAD_MUTEX_INITIALIZER;
pthread_mutex_t mutex4 = PTHREAD_MUTEX_INITIALIZER;

class Scan: public Prefix {

};

struct job {
	string ip;
	string port;
	string scan;
};

struct active {
	string ip;
	string port;
	string scan;
	pthread_t tid;
	int retransmissions;
	double timeStamp;
};

list<active> active_jobs;
list<job> jobs;
list<job> rec_jobs;
struct pseudo_header {
	unsigned int src_add;
	unsigned int dest_add;
	unsigned char pl_holder;
	unsigned char proto;
	unsigned short tcp_len;

	struct tcphdr tcph;
};

struct params {
	string own_ip;
	int count_args;
	char** arg_para;
};

void rec_block();
unsigned short check_sum(unsigned short *hdr, int len)
{
	register long final;
	 unsigned short pad = 0;
	 register short answer;

	 final=0;
	 while(len>1) {
	 final = final + *hdr;
	 hdr++;
	 len-=2;
	 }

	 //if len is odd
	 if(len % 2 != 0)
	 {
	 pad = *(unsigned char *)&pad + *(unsigned char *)hdr;
	 final = final + pad;
	 }



	 while (final>>16) //addition of the octets
	 final = (final & 0xFFFF)+(final >> 16);

	 //cout<<"by new method-> final : "<<(short)~final<<endl;
	 return((short)~final);

}

void print_map(map<int, string> final_map, string s_type , Scan scan) {

	//cout<<"scan.ips.size: "<<scan.ips.size()<<endl;
	std::list<string>::iterator itr;
	for(itr = scan.ips.begin(); itr != scan.ips.end() ; itr++)
	{
		cout<<endl<<"------  "<<*itr<<"  --------"<<endl;
		map<int, string>::iterator it = final_map.begin();
		cout << "----------" << s_type << "---------" << endl;
		while (it != final_map.end()) {
			cout << it->first << " : " << it->second << " : ";
			if (it->first <= max_port)
				cout << port_tcp_service[it->first];
			else
				cout << "UNASSIGNED" << endl;
			service_version(it->first , (char*)( (*itr).c_str() ) );
			++it;
		}
	}
}



void scan_output(unsigned char* buffer, Scan scan, int port_val) {

	struct ip *iph = (struct ip*) buffer;
	unsigned short ip_hdr_len;

	if (iph->ip_p == 6) {
		struct ip *iph = (struct ip *) buffer;
		ip_hdr_len = iph->ip_hl * 4;

		struct icmphdr *icmp = (struct icmphdr*) (buffer + ip_hdr_len);

		struct tcphdr *tcph = (struct tcphdr*) (buffer + ip_hdr_len);

		if ((ack_count || ack_set == 'a')) {
			if ((tcph->rst == 1)) {
				//cout<<"Port is unfiltered"<<endl;
				port_ack_status[port_val] = "UNFILTERED";
			} else {
				//cout<<"Port is filtered"<<endl;
				port_ack_status[port_val] = "FILTERED";
			}
		}

		else if ((syn_count || syn_set == 's')) {
			if ((tcph->syn == 1 && tcph->ack == 1)
					|| (tcph->syn == 1 && tcph->ack == 0)) {
				//cout<<"Port is open"<<endl;
				port_syn_status[port_val] = "OPEN";
			} else if (tcph->rst == 1) {
				//cout<<"Port is closed"<<endl;
				port_syn_status[port_val] = "CLOSED";
			} else {
				//cout<<"Port is filtered"<<endl;
				port_syn_status[port_val] = "FILTERED";
			}
		} else if ((fin_count || fin_set == 'f')) {
			if ((tcph->rst == 1)) {
				//cout<<"Port is closed"<<endl;
				port_fin_status[port_val] = "CLOSED";
			} else {
				//cout<<"Port is open|filtered"<<endl;
				port_fin_status[port_val] = "OPEN|FILTERED";
			}
		} else if ((null_count || null_set == 'n')) {
			if ((tcph->rst == 1)) {
				//cout<<"Port is closed"<<endl;
				port_null_status[port_val] = "CLOSED";
			} else {
				//cout<<"Port is open|filtered"<<endl;
				port_null_status[port_val] = "OPEN|FILTERED";
			}
		} else if ((xmas_count || xmas_set == 'x')) {
			if ((tcph->rst == 1)) {
				//cout<<"Port is closed"<<endl;
				port_xmas_status[port_val] = "CLOSED";
			} else {
				//cout<<"Port is open|filtered"<<endl;
				port_xmas_status[port_val] = "OPEN|FILTERED";
			}
		}

	}
	if (iph->ip_p == 1) {
		struct icmphdr *icmp = (struct icmphdr*) (buffer + ip_hdr_len);
		cout << "ICMP TYPES: " << icmp->type << " -- ICMP CODES: " << icmp->code
				<< endl;
		if ((icmp->type == 3) && (icmp->code == (1 || 2 || 3 || 9 || 10 || 13)))
			cout << "Port is filtered" << endl;
	}

}

Scan init_scan (Scan scan , params *arg) {

	int port_val;
	int ip_val;
	int t = 0;
	//speedup = scan.speedup;
	scan.is_port_set = false;
	scan.is_scan_set = false;
	//scan.total_scan = 1;
	scan.scan_tech = 5;
	scan.scan_count = 0;
	scan.syn_flag = 'z';
	scan.ack_flag = 'z';
	scan.fin_flag = 'z';
	scan.null_flag = 'z';
	scan.xmas_flag = 'z';

	struct params param = *(struct params *) arg;
	scan.evaluate_args(param.count_args, param.arg_para);
	speedup = scan.speedup;

	if (!scan.is_port_set) {
		while (min_port <= max_port) {
			scan.add_port_to_list(scan.convert_i_to_s(min_port), &scan.ports);
			min_port++;
		}
	}

	//cout << "all ports :" << endl;
	std::list<string>::iterator p_it;
	for (p_it = scan.ports.begin(); p_it != scan.ports.end(); p_it++)
		//cout << *p_it << endl;

	if (!scan.is_scan_set) {
		scan.add_scan_type_to_list("SYN", &scan.s_type);
		scan.add_scan_type_to_list("ACK", &scan.s_type);
		scan.add_scan_type_to_list("FIN", &scan.s_type);
		scan.add_scan_type_to_list("NULL", &scan.s_type);
		scan.add_scan_type_to_list("Xmas", &scan.s_type);
		//scan.add_s_type_to_list("UDP" , &scan.s_type);
		ack_count = 1;
		syn_count = 0;
		fin_count = 0;
		null_count = 0;
		xmas_count = 0;
	}

	int jobcount = 0;
	scan.s_type.sort();
	//adding all the jobs to the queue
	std::list<string>::iterator ip_it;
	for (ip_it = scan.ips.begin(); ip_it != scan.ips.end(); ++ip_it) {
		std::list<string>::iterator ip_port;
		for (ip_port = scan.ports.begin(); ip_port != scan.ports.end();
				++ip_port) {
			std::list<string>::iterator ip_scan;
			for (ip_scan = scan.s_type.begin(); ip_scan != scan.s_type.end();
					++ip_scan) {
				job j;		// = new job();
				j.ip = *ip_it;
				j.port = *ip_port;
				j.scan = *ip_scan;
				//cout << "adding scan type :" << j.scan << endl;
				jobs.push_back(j);
				rec_jobs.push_back(j);
				jobcount++;
			}
		}
	}



	if (scan.scan_count > 0)
		scan.scan_tech = scan.scan_count;

	//excluded for trial purposes
	return scan;

}

char* find_own_ip() {
	int ip_sock = socket( AF_INET, SOCK_STREAM, IPPROTO_TCP);

	if (ip_sock < 0)
		cout << "Error creating socket" << endl;

	const char* ip = "129.79.247.87";
	int port = 110;

	struct sockaddr_in server, ip_own;

	server.sin_family = AF_INET;
	server.sin_addr.s_addr = inet_addr(ip);
	server.sin_port = htons(port);

	if ((connect(ip_sock, (const struct sockaddr*) &server, sizeof(server)))
			< 0)
		cout << "Error connecting" << endl;

	socklen_t ip_own_len = sizeof(ip_own);
	getsockname(ip_sock, (struct sockaddr*) &ip_own, &ip_own_len);
	//cout << inet_ntoa(ip_own.sin_addr) << endl;
	close(ip_sock);
	return inet_ntoa(ip_own.sin_addr);
}

void scan_udp_output(unsigned char* buffer) {
	struct ip *iph = (struct ip*) buffer;
	unsigned short ip_hdr_len;

	if (iph->ip_p == 1) {
		struct ip *iph = (struct ip *) buffer;
		ip_hdr_len = iph->ip_hl * 4;

		struct icmphdr *icmp = (struct icmphdr*) (buffer + ip_hdr_len);

		cout << icmp->type << endl;
		cout << icmp->code << endl;
	}
}


void * start_tcp_scan(void * para) {
	Scan scan;
	int port_val;
	int ip_val;
	int t_count = 0;
	bool foundflag = false;
	char packet[2048];

	std::list<active>::iterator active_it;
	//cout << "total jobs :" << jobs.size() << endl;
	while (true) {

		memset(packet, 0, 2048);
		foundflag = false;
		t_count++;
		pthread_mutex_lock(&mutex1);
		if (jobs.empty()) {
			//cout << "Exiting" << endl;
			pthread_mutex_unlock(&mutex1);
			break;
		}
		job j = jobs.front();
		jobs.pop_front();
		pthread_mutex_unlock(&mutex1);

		struct sockaddr_in send_dest;
		int sock_to_send;
		char* temp_port;
		char* ch;
		memset(&temp_port, 0, 1);
		memset(&ch, 0, 1);
		ch = (char*) (j.port.c_str());
		scan.port = strtol(ch, &temp_port, 10);
		port_val = scan.port;
		scan.ipadr = (char *) j.ip.c_str();

		//cout<<"portval : "<<port_val<<" scan.ipadr : "<<scan.ipadr<<endl;
		send_dest.sin_family = AF_INET;
		send_dest.sin_port = htons(scan.port);
		send_dest.sin_addr.s_addr = inet_addr(scan.ipadr);


		//check if job's scan is of type UDP
		bool isudp = false;
		if (strcmp(j.scan.c_str(),"UDP") == 0)
			isudp = true;

		if (isudp)
		{
			sock_to_send = socket(AF_INET, SOCK_RAW, IPPROTO_UDP);
			if (sock_to_send < 0) {
				cout << "The socket is not created: " << endl;
				exit(0);
			}

			struct udphdr *udp = (struct udphdr *) packet;	// + sizeof(iphdr));
			udp->source = htons(13342);
			udp->dest = htons(port_val);
			udp->len = htons(sizeof(struct udphdr));
			udp->check = 0;

			if(port_val == 53)
			{
				struct DNS_HEADER *dns = (struct DNS_HEADER*) (packet
						+ sizeof(struct udphdr));
				//Set the DNS structure to standard queries
				dns->id = (unsigned short) htons(getpid());
				dns->qr = 0; //This is a query
				dns->opcode = 0; //This is a standard query
				dns->aa = 0; //Not Authoritative
				dns->tc = 0; //This message is not truncated
				dns->rd = 1; //Recursion Desired
				dns->ra = 0; //Recursion not available! hey we dont have it (lol)
				dns->z = 0;
				dns->ad = 0;
				dns->cd = 0;
				dns->rcode = 0;
				dns->q_count = htons(1); //we have only 1 question
				dns->ans_count = 0;
				dns->auth_count = 0;
				dns->add_count = 0;
				dns->qname = '\0';
				dns->qclass = htons(1);
				dns->qtype = htons(1);

				udp->len = htons(
						sizeof(struct udphdr) + sizeof(struct DNS_HEADER));

			}


		} else {//tcp block
			sock_to_send = socket(AF_INET, SOCK_RAW, IPPROTO_TCP);
			if (sock_to_send < 0) {
				cout << "The socket is not created: " << endl;
				exit(0);
			}


			struct iphdr *iph = (struct iphdr *) packet;
			struct tcphdr *tcp = (struct tcphdr *) (packet + sizeof(iphdr));

			struct pseudo_header psh;
			struct params param = *(struct params *) para;

			iph->ihl = 5;
			iph->version = 4;
			iph->tos = 0;
			iph->ttl = ~0;
			iph->tot_len = sizeof(struct iphdr) + sizeof(struct tcphdr);
			iph->id = htons(23343);
			iph->frag_off = htons(16384);
			iph->protocol = IPPROTO_TCP;
			iph->check = 0;
			iph->saddr = inet_addr(param.own_ip.c_str());
			iph->daddr = inet_addr(scan.ipadr);
			iph->check = check_sum((unsigned short *) packet, iph->tot_len >> 1);

			tcp->source = htons(13333);
			tcp->seq = htonl(1105024978);
			tcp->ack_seq = 0;
			tcp->doff = 5;
			tcp->syn = tcp->fin = tcp->psh = tcp->urg = tcp->ack = tcp->rst = 0;
			if (strcmp((char *) j.scan.c_str(), "SYN") == 0)
				tcp->syn = 1;
			else if (strcmp((char *) j.scan.c_str(), "ACK") == 0)
				tcp->ack = 1;
			else if (strcmp((char *) j.scan.c_str(), "FIN") == 0)
				tcp->fin = 1;
			else if (strcmp((char *) j.scan.c_str(), "NULL") == 0) {
			} else if (strcmp((char *) j.scan.c_str(), "Xmas") == 0) {
				tcp->fin = 1;
				tcp->psh = 1;
				tcp->urg = 1;
			} else {
				cout << "SCAN type didn't match!!" << endl;
				exit(1);
			}

			tcp->window = htons(14600);
			tcp->check = 0;
			tcp->urg_ptr = 0;

			tcp->dest = htons(scan.port);
			//cout<<"ntohs(tcp->dest) :"<<ntohs(tcp->dest)<<endl;

			psh.src_add = inet_addr(param.own_ip.c_str()); //(char*)param.own_ip.c_str());
			psh.dest_add = send_dest.sin_addr.s_addr;
			psh.pl_holder = 0;
			psh.proto = IPPROTO_TCP;
			psh.tcp_len = htons(sizeof(struct tcphdr));

			memcpy(&psh.tcph, tcp, sizeof(struct tcphdr));

			tcp->check = check_sum((unsigned short*) &psh,
					sizeof(struct pseudo_header));

			int a = 1;
			const int* value = &a;

			if ((setsockopt(sock_to_send, IPPROTO_IP, IP_HDRINCL, &value,
					sizeof(a))) < 0) {
				cout << "Error in setsockopt: " << errno << " --- "
						<< strerror(errno) << endl;
				exit(0);
			}
		}//else block ends(scan is TCP for this else)

		//if job having same ip and port is present in active_jobs, just push it back to the jobs queue and continue
		pthread_mutex_lock(&mutex2); //for active jobss
		pthread_mutex_lock(&mutex1); // for jobs
		for (active_it = active_jobs.begin(); active_it != active_jobs.end();
				active_it++)
			if (active_it->ip == j.ip && active_it->port == j.port) {
				jobs.push_back(j);
				//cout << "job pushed back, value of count : " << t_count << endl;
				foundflag = true;
				pthread_mutex_unlock(&mutex2);
				pthread_mutex_unlock(&mutex1);
				//close(sock_to_send);
				break;
			}
		if (foundflag) {
			sleep(1);
			continue;
		}

		pthread_mutex_unlock(&mutex2);
		pthread_mutex_unlock(&mutex1);
		bool smooth = true;
		if (isudp) {
			if (port_val == 53) {
				if ((sendto(sock_to_send, packet,
						sizeof(struct udphdr) + sizeof(struct DNS_HEADER), 0,
						(struct sockaddr *) &send_dest, sizeof(send_dest)))
						< 0) {
					cout << "Error in sendto: " << errno << " --- "
							<< strerror(errno) << endl;
					smooth = false;
					exit(0);
				}
			} else {
				if ((sendto(sock_to_send, packet, sizeof(struct udphdr), 0,
						(struct sockaddr *) &send_dest, sizeof(send_dest)))
						< 0) {
					cout << "Error in sendto: " << errno << " --- "
							<< strerror(errno) << endl;
					smooth = false;
					exit(0);
				}
			}

		}
		else // sendto for tcp
		if ((sendto(sock_to_send, packet,sizeof(struct iphdr) + sizeof(struct tcphdr), 0,
				(struct sockaddr *) &send_dest, sizeof(send_dest))) < 0) {
			cout << "Error in sendto: " << errno << " --- " << strerror(errno)<< endl;
			smooth = false;
			exit(0);
		}
		if(smooth){
			pthread_mutex_lock(&mutex2);
			//cout << "Sending, value of count : " << t_count << endl;
			time_t t = time(NULL);
			active a;
			a.ip = j.ip;
			a.port = j.port;
			a.scan = j.scan;
			a.tid = pthread_self();
			a.timeStamp = t;
			active_jobs.push_back(a);
			//cout << "size of active jobs : " << active_jobs.size() << endl;
			pthread_mutex_unlock(&mutex2);
			sleep(0.1);
		}
		close (sock_to_send);
	}
	//rec_block();
}

void parse_buf(unsigned char * recv_buf, int type, string self_ip) {
	std::list<active>::iterator active_it;
	if (type == 1)        //tcp
			{
		struct ip *iph = (struct ip*) recv_buf;
		unsigned short ip_hdr_len;
		if (iph->ip_p == 6) {
			struct ip *iph = (struct ip *) recv_buf;
			ip_hdr_len = iph->ip_hl * 4;
			struct tcphdr *tcph = (struct tcphdr*) (recv_buf + ip_hdr_len);

			pthread_mutex_lock(&mutex2);
			for (active_it = active_jobs.begin();active_it != active_jobs.end(); active_it++) {
				uint16_t temp_port = (uint16_t) atoi(active_it->port.c_str()); //for converting first from string to char* and then to int

				if (strcmp(inet_ntoa(iph->ip_src), active_it->ip.c_str()) == 0
						&& strcmp(inet_ntoa(iph->ip_dst), self_ip.c_str()) == 0
						&& (temp_port == ntohs(tcph->source))) {


					if ((tcph->syn == 1 && tcph->ack == 1)
							|| (tcph->syn == 1 && tcph->ack == 0))
					{
						if(strcmp(active_it->scan.c_str(),"SYN")==0)
						port_syn_status[ntohs(tcph->source)] = "OPEN";

						else if(strcmp(active_it->scan.c_str(),"ACK")==0)
						port_ack_status[ntohs(tcph->source)] = "UNFILTERED";

						else if (strcmp(active_it->scan.c_str(), "FIN") == 0)
							port_fin_status[ntohs(tcph->source)] = "OPEN | FILTERED";
						else if(strcmp(active_it->scan.c_str(), "NULL") == 0)
							port_null_status[ntohs(tcph->source)] = "OPEN | FILTERED";
						else if(strcmp(active_it->scan.c_str(), "Xmas") == 0)
							port_xmas_status[ntohs(tcph->source)] = "OPEN | FILTERED";
					}

					else if (tcph->rst == 1)
					{
						if(strcmp(active_it->scan.c_str(),"SYN")==0)
						port_syn_status[ntohs(tcph->source)] = "CLOSED";

						else if(strcmp(active_it->scan.c_str(),"ACK")==0)
							port_ack_status[ntohs(tcph->source)] = "UNFILTERED";
						else if (strcmp(active_it->scan.c_str(), "FIN") == 0)
							port_fin_status[ntohs(tcph->source)] =	"CLOSED";
						else if (strcmp(active_it->scan.c_str(), "NULL") == 0)
							port_null_status[ntohs(tcph->source)] =	"CLOSED";
						else if (strcmp(active_it->scan.c_str(), "Xmas") == 0)
							port_xmas_status[ntohs(tcph->source)] = "CLOSED";
					}

					else
						port_syn_status[ntohs(tcph->source)] = "FILTERED";


				//cout<<"-------------------------------------- recieved the job-----------------------"<<endl;
				recieved_jobs++;
				//pthread_mutex_lock(&mutex2);
				active_jobs.erase(active_it);
				pthread_mutex_unlock(&mutex2);
				sleep(0.5);
				break;
				}
			} pthread_mutex_unlock(&mutex2);
		}
	}

	else if(type == 2)//udp
			{
		struct ip *iph = (struct ip*) recv_buf;
		unsigned short ip_hdr_len;
		if (iph->ip_p == 17) //confirmed udp
				{
			struct udphdr *udph = (struct udphdr*) (recv_buf + ip_hdr_len);

			pthread_mutex_lock(&mutex2);
			for (active_it = active_jobs.begin();
					active_it != active_jobs.end(); active_it++) {
				uint16_t temp_port = (uint16_t) atoi(active_it->port.c_str()); //for converting first from string to char* and then to int
				if (strcmp(inet_ntoa(iph->ip_src), active_it->ip.c_str()) == 0
						&& strcmp(inet_ntoa(iph->ip_dst), self_ip.c_str()) 	== 0
						&& (temp_port == ntohs(udph->source))) {

					port_udp_scan[temp_port] = "OPEN";
					active_jobs.erase(active_it);
					pthread_mutex_unlock(&mutex2);
					break;
				}
			}pthread_mutex_unlock(&mutex2);
		}
	}
	else if(type == 3){ //icmp
		struct ip *iph = (struct ip*) recv_buf;
		unsigned short ip_hdr_len;
		if (iph->ip_p == 1){
			struct icmphdr *icmp = (struct icmphdr*)(recv_buf + ip_hdr_len);
			pthread_mutex_lock(&mutex2);
			for (active_it = active_jobs.begin();active_it != active_jobs.end(); active_it++){

				uint16_t temp_port = (uint16_t) atoi(active_it->port.c_str()); //for converting first from string to char* and then to int

				if (strcmp(inet_ntoa(iph->ip_src), active_it->ip.c_str()) == 0
							&& strcmp(inet_ntoa(iph->ip_dst), self_ip.c_str()) == 0
							//&& strcmp(active_it->scan.c_str(),"UDP")==0
							)
							//&& (temp_port == ntohs(icmp->source)))

				{
					/*if(icmp->type == 3 && icmp->code==3 )
					{
						//port_udp_scan[atoi(active_it->port.c_str())] = "CLOSED";
						//active_jobs.erase(active_it);
						pthread_mutex_unlock(&mutex2);
						break;
					}*/
					//cout<<"recieved icmp for temp_port"<<endl;
									//port_udp_scan[active_it->port] = "OPEN";
								}

			}pthread_mutex_unlock(&mutex2);
		}
	}
}

void * rec_block(void * para)
//void rec_block()
		{
	Scan scan;
	unsigned char* recv_buf_icmp = (unsigned char*) malloc(2048);
	unsigned char* recv_buf_tcp = (unsigned char*) malloc(2048);
	unsigned char* recv_buf_udp = (unsigned char*) malloc(2048);
	bzero(recv_buf_icmp, sizeof(recv_buf_icmp));
	bzero(recv_buf_tcp, sizeof(recv_buf_tcp));
	bzero(recv_buf_udp, sizeof(recv_buf_udp));
	struct sockaddr_in recv_dest_icmp;
	struct sockaddr_in recv_dest_tcp;
	struct sockaddr_in recv_dest_udp;
	int length_tcp;
	//socklen_t length_tcp;
	int length_icmp;
	//length_tcp = sizeof(recv_dest_tcp);
	int length_udp;
	length_icmp = sizeof(recv_dest_icmp);
	length_udp = sizeof(recv_dest_udp);
	length_tcp = sizeof(recv_dest_tcp);

	int sock_to_recv_icmp;
	int sock_to_recv_tcp;
	int sock_to_recv_udp;

	struct params param = *(struct params *) para;
	sock_to_recv_icmp = socket(AF_INET, SOCK_RAW, IPPROTO_ICMP);
	sock_to_recv_tcp = socket(AF_INET, SOCK_RAW, IPPROTO_TCP);
	sock_to_recv_udp = socket(AF_INET, SOCK_RAW, IPPROTO_UDP);

	if (sock_to_recv_tcp < 0) {
		cout << "Error in sock_to_recv: " << errno << " --- " << strerror(errno)
				<< endl;
		exit(0);
	}

	if (sock_to_recv_icmp < 0) {
		cout << "Error in sock_to_recv: " << errno << " --- " << strerror(errno)
				<< endl;
		exit(0);
	}
	if (sock_to_recv_udp < 0) {
		cout << "Error in sock_to_recv: " << errno << " --- " << strerror(errno)
				<< endl;
		exit(0);
	}
	/*
	 fcntl(sock_to_recv_tcp, F_SETFL, O_NONBLOCK);
	 fcntl(sock_to_recv_icmp, F_SETFL, O_NONBLOCK);*/
	struct pollfd sock_val[3];
	sock_val[0].fd = sock_to_recv_icmp;
	sock_val[1].fd = sock_to_recv_tcp;
	sock_val[2].fd = sock_to_recv_udp;

	sock_val[0].events = POLLIN;
	sock_val[1].events = POLLIN;
	sock_val[2].events = POLLIN;

	int wait;

	do {
		wait = poll(sock_val, 3, 6000);
		//cout << "something recieved!  " << endl;
		if (wait == -1)
			cout << "error while polling !" << endl;
		else if (wait == 0)
			{}//cout << "Time out!!" << endl;
		else {
			if (sock_val[0].revents & POLLIN) {
				//cout << "Inside ICMP" << endl;
				int bytes_recd = -1;
				if ((bytes_recd = recvfrom(sock_to_recv_icmp, recv_buf_icmp,
						2048, 0, (struct sockaddr *) &recv_dest_icmp,
						(socklen_t *) &length_icmp)) < 0) {
					cout << "error in receiving icmp :" << errno
							<< " description : " << strerror(errno) << endl;
					exit(0);
				} else {
					//cout << "recieved icmp! " << endl;
					//parse_buf(recv_buf_icmp, 3, param.own_ip);
				}
			}

			if (sock_val[1].revents & POLLIN) {
				//cout << "Inside tcp" << endl;
				int bytes_recd = -1;
				if ((bytes_recd = recvfrom(sock_to_recv_tcp, recv_buf_tcp, 2048,
						0, (struct sockaddr *) &recv_dest_tcp,
						(socklen_t *) &length_tcp)) < 0) {
					cout << "error in receiving tcp :" << errno
							<< " description : " << strerror(errno) << endl;
					exit(0);
				} else {
					//cout<<"going to parsebuff+++++++++++++"<<endl;
					parse_buf(recv_buf_tcp, 1, param.own_ip);
				}
			}

			if (sock_val[2].revents & POLLIN) {
				//cout << "Inside udp" << endl;
				int bytes_recd = -1;
				if ((bytes_recd = recvfrom(sock_to_recv_udp, recv_buf_udp, 2048,
						0, (struct sockaddr *) &recv_dest_udp,
						(socklen_t *) &length_udp)) < 0) {
					cout << "error in receiving udp :" << errno
							<< " description : " << strerror(errno) << endl;
					exit(0);
				} else {
					//cout << "recieved udp! " << endl;
					parse_buf(recv_buf_udp, 2, param.own_ip);
				}
			}
		}
		pthread_mutex_lock(&mutex2);
		pthread_mutex_lock(&mutex1);
		//cout<< "checking size of active_jobs and jobs in rec_block mutex! SIZE : "<< active_jobs.size() << endl;
		if (active_jobs.size() == 0 && jobs.size() == 0) {
			pthread_mutex_unlock(&mutex1);
			pthread_mutex_unlock(&mutex2);
			break;
		}
		pthread_mutex_unlock(&mutex1);
		pthread_mutex_unlock(&mutex2);
		sleep(0.1);
		//cout<<"before completing the while loop in rec_block(), jobs.size = "<<jobs.size()<<endl;
	} while (true);
	//cout << "rec_block() exited!! ------------------------------------" << endl;

	free(recv_buf_icmp);
	free(recv_buf_udp);
	free(recv_buf_tcp);
	close(sock_to_recv_icmp);
	close(sock_to_recv_tcp);
	close(sock_to_recv_udp);
}

void * check_actives(void * para) {
	sleep(3);
	while (true) {
		sleep(1);
		time_t now = time(NULL);
		std::list<active>::iterator it;
		pthread_mutex_lock(&mutex2);
		for (it = active_jobs.begin(); it != active_jobs.end(); ++it) {
			//cout<<"timdiff :"<<(now - it->timeStamp)<<endl;
			if ((now - it->timeStamp) > 5) {

				if (strcmp(it->scan.c_str(), "UDP") == 0)
					port_udp_scan[atoi(it->port.c_str())] = "OPEN|FILTERED";
				if (strcmp(it->scan.c_str(), "SYN") == 0)
					port_syn_status[atoi(it->port.c_str())] = "FILTERED";
				else if (strcmp(it->scan.c_str(), "ACK") == 0)
					port_ack_status[atoi(it->port.c_str())] = "FILTERED";
				else if (strcmp(it->scan.c_str(), "FIN") == 0)
					port_fin_status[atoi(it->port.c_str())] = "OPEN | FILTERED";
				else if (strcmp(it->scan.c_str(), "NULL") == 0)
					port_null_status[atoi(it->port.c_str())] = "OPEN | FILTERED";
				else if (strcmp(it->scan.c_str(), "Xmas") == 0)
					port_xmas_status[atoi(it->port.c_str())] = "OPEN | FILTERED";

				deleted_jobs++;
				/*cout << "deleting ip : " << it->ip << " port : " << it->port<<it->scan
						<< " because of timeout! seconds - "
						<< (now - it->timeStamp) << endl;*/
				it = active_jobs.erase(it);
			}

		}
		pthread_mutex_lock(&mutex1);
		//cout<<"jobs.size :"<<jobs.size()<<endl;
		if (active_jobs.size() == 0 && jobs.size() == 0) {
			//cout << "++++++++++++++++++ Exiting check_actives() !" << endl;
			pthread_mutex_unlock(&mutex1);
			pthread_mutex_unlock(&mutex2);
			break;
		}
		pthread_mutex_unlock(&mutex1);
		pthread_mutex_unlock(&mutex2);
	}

}

int main(int argc, char* argv[])
//int main()
		{
	Scan scan;
	time_t start_time = time(NULL);
	//cout << endl << endl << "start time :" << start_time <<" : scan.ips.size()-"<<scan.ips.size()<< endl;
	string ch;
	recieved_jobs = 0;
	deleted_jobs = 0;

	ch = find_own_ip();

	add_tcp_services();
	add_udp_services();

	params para;
	para.count_args = argc;
	para.arg_para = argv;
	para.own_ip = ch;
	//to initialize jobs
	//scan.evaluate_args(para.count_args, para.arg_para);
	scan = init_scan(scan , &para);

	pthread_t th[speedup];

	//single threads for rec and check
	pthread_t t_rec;
	pthread_t t_check;

	//cout << "speedup : " << speedup << endl;
	for (int cnt = 0; cnt < speedup; cnt++) {
		if (pthread_create(&th[cnt], NULL, start_tcp_scan, &para))
			cout << "Error with thread1" << endl;
	}

	if (pthread_create(&t_rec, NULL, rec_block, &para))
		cout << "Error with thread2" << endl;

	if (pthread_create(&t_check, NULL, check_actives, &para))
		cout << "Error with thread1" << endl;

	for (int join_cnt = 0; join_cnt < speedup; join_cnt++)
		pthread_join(th[join_cnt], NULL);

	pthread_join(t_rec, NULL);
	pthread_join(t_check, NULL);

	if(port_syn_status.size()!=0)
	print_map(port_syn_status , "SYN" , scan);
	if(port_ack_status.size()!=0)
	print_map(port_ack_status,"ACK", scan);
	if(port_fin_status.size()!=0)
	print_map(port_fin_status,"FIN", scan);
	if(port_null_status.size()!=0)
	print_map(port_null_status,"NULL", scan);
	if(port_xmas_status.size()!=0)
	print_map(port_xmas_status,"Xmas", scan);
	if(port_udp_scan.size()!=0)
	print_map(port_udp_scan,"UDP", scan);

	time_t end_time = time(NULL);
	//cout << "  Total time :"
			//<< (double) (end_time - start_time);
	//cout << " | total jobs recieved : " << recieved_jobs;
	//cout << " | total jobs deleted : " << deleted_jobs << endl;

	//start_udp_scan();

	return 0;

}

