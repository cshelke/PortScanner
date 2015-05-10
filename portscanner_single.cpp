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
#include<time.h>
#include<algorithm>
#include "prefix.cpp"
#include "ip.h"
#include "tcp.h"
#include "ip_icmp.h"
#include "services.h"
#include "udp.h"
#include "find_service_and_version.h"
#include "checksum_and_selfip.h"
#include "reference_structures.h"

using namespace std;

int syn_count;
int ack_count;
int fin_count;
int xmas_count;
int null_count;
char syn_set,ack_set,fin_set;
char null_set,xmas_set;
int min_port = 1;
int max_port = 1024;
map<int,string> port_ack_status;
map<int,string> port_syn_status;
map<int,string> port_fin_status;
map<int,string> port_null_status;
map<int,string> port_xmas_status;
map<int,string> port_udp_scan;
list<char>conclusion;
class Scan: public Prefix
{

};

void print_udp_results(map<int,string>final_udp_map , char* ip , int port_val)
{
	cout<<port_val<<" : "<<final_udp_map[port_val]<<" : ";
        if(port_val <= max_port)
                cout<<port_udp_service[port_val];
        else
                cout<<"UNASSIGNED"<<endl;
        service_version(port_val , ip);
}

void scan_udp_output(unsigned char* buffer , Scan scan , int port_val , char* temp_ip , string self_ip)
{
        struct ip *iph = (struct ip*)buffer;

        unsigned short ip_hdr_len;
        ip_hdr_len = iph->ip_hl*4;

        if(iph->ip_p == 17)
        {
                struct udphdr *udph=(struct udphdr*)(buffer + ip_hdr_len);
                if( ( strcmp( inet_ntoa(iph->ip_src) , temp_ip ) == 0 ) && ( strcmp( inet_ntoa(iph->ip_dst) ,(char*)self_ip.c_str()) == 0 ) )
		{
                        port_udp_scan[port_val] = "OPEN";
			conclusion.push_back('O');
		}
                else
		{
                        port_udp_scan[port_val] = "OPEN|FILTERED";
			conclusion.push_back('Y');
		}
        }

        if(iph->ip_p == 1)
        {
                struct icmphdr *icmp = (struct icmphdr*)(buffer + ip_hdr_len);
                if( ( strcmp( inet_ntoa(iph->ip_src) , temp_ip ) == 0 ) && ( strcmp( inet_ntoa(iph->ip_dst) ,(char*)self_ip.c_str()) == 0 ) )
                {
                        if( (int)icmp->type == 3 && (int)icmp->code == (1||2||9||10||13) )
			{
                                port_udp_scan[port_val] = "FILTERED";
				conclusion.push_back('F');
			}

                        else if ( (int)icmp->type == 3 && (int)icmp->code == 3 )
			{
                                port_udp_scan[port_val] = "CLOSED";
				conclusion.push_back('C');
			}
                }
                else
			{
                        	port_udp_scan[port_val] = "OPEN|FILTERED";
				conclusion.push_back('Y');
			}
        }
}

void start_udp_scan(Scan scan , char* dest_ip , string self_ip)
{

	
        int count = 3;

        int port_val;
        int flag = 0;
        char packet[3192];
        memset(packet , 0 ,3192);

        struct udphdr *udp = (struct udphdr *)packet;

        struct sockaddr_in server;

        unsigned char* recv_buf_icm = (unsigned char*)malloc(2048);
        unsigned char* recv_buf_ud = (unsigned char*)malloc(2048);
	int sock_recv_icm , sock_recv_ud;
        bzero(recv_buf_icm, sizeof(recv_buf_icm));
        int sock = socket ( AF_INET, SOCK_RAW, IPPROTO_UDP);

        if(sock < 0){
                cout<<"Error in socket_creation: "<<errno<<" --- "<<strerror(errno)<<endl;
		exit(0);
	}

                std::list<string>::iterator itr;
                for(itr = scan.ports.begin() ; itr != scan.ports.end() ; ++itr)
                {

                        unsigned char* recv_buf = (unsigned char*)malloc(65536);
                        char* temp_port;
                        char* ch;
                        memset(&temp_port,0,1);
                        memset(&ch,0,1);
                        ch = (char*)((*itr).c_str());
                        scan.port = strtol(ch , &temp_port , 10);
                        port_val = scan.port;

                        server.sin_family = AF_INET;
                        server.sin_addr.s_addr = inet_addr(dest_ip);
                        server.sin_port = htons( port_val );

                        udp->source = htons(11142);
                        udp->dest = htons( port_val );
                        udp->len = htons(sizeof(struct udphdr));
                	while(count != 0)
                	{
                        	if(port_val == 53)
                        	{
                                	struct DNS_HEADER *dns = (struct DNS_HEADER*)(packet + sizeof(struct udphdr));

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
	
        	                        udp->len = htons( sizeof(struct udphdr) + sizeof(struct DNS_HEADER) );

                	                if((sendto(sock , packet , sizeof(struct udphdr) + sizeof(struct DNS_HEADER) , 0 , (struct sockaddr *)&server , sizeof(server))) < 0){
                        	        	cout<<"Error in sendto: "<<errno<<" --- "<<strerror(errno)<<endl;
	                                	exit(0);
        	                        }
                	        }
                        	else
	                        {
        	                        if((sendto(sock , packet , sizeof(struct udphdr) , 0 , (struct sockaddr *)&server , sizeof(server))) < 0)
                	                {
                        	                cout<<"Error in sendto: "<<errno<<" --- "<<strerror(errno)<<endl;
                                	        exit(0);
	                                }
        	                }
                	        
                        	sock_recv_icm = socket(AF_INET , SOCK_RAW , IPPROTO_ICMP);
	                        sock_recv_ud = socket(AF_INET , SOCK_RAW , IPPROTO_UDP);
        	                if(sock_recv_icm < 0){
                	                cout<<"Error in sock_to_recv: "<<errno<<" --- "<<strerror(errno)<<endl;
                        	        exit(0);
	                        }

        	                if(sock_recv_ud < 0){
                	                cout<<"Error in sock_to_recv: "<<errno<<" --- "<<strerror(errno)<<endl;
					exit(0);
				}
	
        	                struct sockaddr_in recv_dest_icm;
                	        struct sockaddr_in recv_dest_ud;
                        	int length_icm;
	                        int length_ud;
        	                length_icm = sizeof(recv_dest_icm);
                	        length_ud = sizeof(recv_dest_ud);

                        	struct pollfd sock_scan[2];
	                        sock_scan[0].fd = sock_recv_icm;
        	                sock_scan[0].events = POLLIN;
                	        sock_scan[1].fd = sock_recv_ud;
                        	sock_scan[1].events = POLLIN;

	                        int wait;
        	                wait = poll(sock_scan , 2 , 7000);
                	        if(wait == -1)
                        	        cout<<"Error"<<endl;
	                        else if(wait == 0)
        	                        cout<<"Timeout"<<endl;
                	        else
                        	{
                                	if(sock_scan[0].revents & POLLIN)
	                                {
        	                                int bytes_received=-1;
                	                        if((bytes_received=recvfrom(sock_recv_icm , recv_buf_icm , 2048  , 0 , (struct sockaddr *)&recv_dest_icm , (socklen_t*)&length_icm)) < 0)
                        	                {
                                	                cout<<"Error in recvfrom: "<<errno<<" --- "<<strerror(errno)<<endl;
                                        	        exit(0);
	                                        }
        	                                else
                	                        {
                        	                        flag = 1;
                                	                break;
                                        	}
                                	}
	                                if(sock_scan[1].revents & POLLIN)
        	                        {
                	                        if(recvfrom(sock_recv_ud , recv_buf_ud , 2048  , 0 , (struct sockaddr *)&recv_dest_ud , (socklen_t*)&length_ud) < 0)
                        	                {
                                	                cout<<"Error in recvfrom: "<<errno<<" --- "<<strerror(errno)<<endl;
                                        	        exit(0);
	                                        }
        	                        }
                	        }
		        count--;
                	}
			//free(recv_buf_icm);
                        close(sock_recv_icm);
                        //free(recv_buf_ud);
                        close(sock_recv_ud);
                        if(flag)
                                scan_udp_output(recv_buf_icm , scan , atoi( (char*)((*itr).c_str()) ) , dest_ip , self_ip);
                        else
                                scan_udp_output(recv_buf_ud , scan , atoi( (char*)((*itr).c_str()) ) , dest_ip , self_ip);
                }

        close(sock);

}

void print_conclusion(int port_val)
{
	cout<<"----CONCLUSION----"<<endl;
	int size = conclusion.size();
	
	
	std::list<char>::iterator ito;
	std::list<char>::iterator itu;
	std::list<char>::iterator itf;
	std::list<char>::iterator itc;
	std::list<char>::iterator itof;
	ito = find (conclusion.begin(), conclusion.end(), 'O');
	itu = find (conclusion.begin(), conclusion.end(), 'U');
	itc = find (conclusion.begin(), conclusion.end(), 'C');
	itf = find (conclusion.begin(), conclusion.end(), 'F');
	itof = find (conclusion.begin(), conclusion.end(), 'Y');
	
	cout<<"Port "<<port_val;
	if(*ito)
		cout<<" is OPEN"<<endl;
	else if(*itc)
                cout<<" is CLOSED"<<endl;
	else if(*itf && *itof)
		cout<<" is FILTERED"<<endl;
	else if( *itof || (*itu && *itof) )
		cout<<" is OPEN|FILTERED"<<endl;
	else if(*itf)
		cout<<" is FILTERED"<<endl;
	else if(*itu)
                cout<<" is UNFILTERED"<<endl;
	
	
}
void print_map(map<int,string>final_map , string scan_type , int port_val , char* ip)
{
	cout<<"----------"<<scan_type<<"-----------"<<endl;
	cout<<port_val<<" : "<<final_map[port_val]<<" : ";
	if(port_val <= max_port)
		cout<<port_tcp_service[port_val];
	else
		cout<<"UNASSIGNED"<<endl;
	service_version(port_val , ip);
}

void print_scan_status(Scan scan , char* ip , int port_val)
{
	
	int default_scan;
	if(scan.scan_count == 0)
	{
		default_scan = 5;
		ack_count = 1;
	}
	else
	{
		default_scan = scan.scan_count;
		ack_set = scan.ack_flag;
		syn_set = scan.syn_flag;
                fin_set = scan.fin_flag;
                null_set = scan.null_flag;
                xmas_set = scan.xmas_flag;
	}

	while(default_scan != 0)
	{
		if(!scan.is_scan_set)
		{
			if(ack_count == 1){
	                        syn_count = 1; ack_count = 0;
                	        print_map(port_ack_status , "ACK" , port_val , ip);
        	        }
			else if(syn_count == 1 ){
                	        fin_count = 1; syn_count = 0;
        	                print_map(port_syn_status , "SYN" , port_val , ip);
	                }
			else if(fin_count == 1){
        	               	null_count = 1; fin_count = 0;
	                        print_map(port_fin_status , "FIN" , port_val , ip);
                	}
			else if(null_count == 1){
	                        xmas_count = 1; null_count = 0;
                	        print_map(port_null_status , "NULL" , port_val , ip);
        	        }
			else if(xmas_count == 1 ){
                        	xmas_count = 0;
                	        print_map(port_xmas_status , "Xmas" , port_val , ip);
        	        }	
		}
		else
		{
			if(ack_set == 'a')
			{
				ack_set = 'z';
				print_map(port_ack_status , "ACK" , port_val , ip);
			}
			else if(syn_set == 's')
			{
				syn_set = 'z';
				print_map(port_syn_status , "SYN" , port_val , ip);
			}
			else if(fin_set == 'f')
			{
				fin_set = 'z';
				print_map(port_fin_status , "FIN" , port_val , ip);
			}
			else if(null_set == 'n')
			{
				null_set = 'z';
				print_map(port_null_status , "NULL" , port_val , ip);
			}
			else if(xmas_set == 'x')
			{
				xmas_set = 'z';
				print_map(port_xmas_status , "Xmas" , port_val , ip);
			}
		}
	default_scan--;
	}
	
}

void scan_output(unsigned char* buffer , Scan scan , int port_val)
{
  
	struct ip *iph = (struct ip*)buffer;
	unsigned short ip_hdr_len;
 
        if(iph->ip_p == 6)
        {
		struct ip *iph = (struct ip *)buffer;
        	ip_hdr_len = iph->ip_hl*4;

		struct icmphdr *icmp = (struct icmphdr*)(buffer + ip_hdr_len);
     
        	struct tcphdr *tcph=(struct tcphdr*)(buffer + ip_hdr_len);
	
		if( (ack_count || ack_set == 'a') )
                {
                        if((tcph->rst == 1))
			{
				port_ack_status[port_val] = "UNFILTERED";
				conclusion.push_back ('U');
			}
                        else
			{
				port_ack_status[port_val] = "FILTERED";
				conclusion.push_back ('F');
			}
                }

    		else if( (syn_count || syn_set == 's') )
		{
        		if((tcph->syn == 1 && tcph->ack == 1) || (tcph->syn == 1 && tcph->ack == 0))
			{
				port_syn_status[port_val] = "OPEN";
				conclusion.push_back ('O');
			}
			else if(tcph->rst == 1)
			{
				port_syn_status[port_val] = "CLOSED";
				conclusion.push_back ('C');
			}
			else
			{
				port_syn_status[port_val] = "FILTERED";
				conclusion.push_back ('F');
			}
		}
		else if( (fin_count || fin_set == 'f') )
                {
                        if((tcph->rst == 1))
			{
				port_fin_status[port_val] = "CLOSED";
				conclusion.push_back ('C');
			}
                        else
                 	{
				port_fin_status[port_val] = "OPEN|FILTERED";
				conclusion.push_back ('Y');
			}
                }
		else if( (null_count || null_set == 'n') )
		{
			if((tcph->rst == 1))
			{
				port_null_status[port_val] = "CLOSED";
				conclusion.push_back ('C');
			}
                        else
			{
				port_null_status[port_val] = "OPEN|FILTERED";
				conclusion.push_back ('Y');
			}
		}
		else if( (xmas_count || xmas_set == 'x') )
		{
			if((tcph->rst == 1))
			{
				port_xmas_status[port_val] = "CLOSED";
				conclusion.push_back ('C');
			}
                        else
			{
				port_xmas_status[port_val] = "OPEN|FILTERED";
				conclusion.push_back ('Y');
			}
		}

	}
	if(iph->ip_p == 1)
	{
		struct icmphdr *icmp = (struct icmphdr*)(buffer + ip_hdr_len);
		if((icmp->type == 3) && (icmp->code == (1 || 2 || 3 || 9 || 10 || 13)))
		{
			if( (ack_count || ack_set == 'a') )
				port_ack_status[port_val] = "FILTERED";
			else if( (syn_count || syn_set == 's') )
				port_syn_status[port_val] = "FILTERED";
			else if( (fin_count || fin_set == 'f') )
				port_fin_status[port_val] = "FILTERED";
			else if( (null_count || null_set == 'n') )
				port_null_status[port_val] = "FILTERED";
			else if( (xmas_count || xmas_set == 'x') )
				port_xmas_status[port_val] = "FILTERED";
		}
	}

}

void * start_tcp_scan(void * arg)
{

	Scan scan;
	int port_val;
	int ip_val;
	int t = 0;
        scan.is_port_set = false;
	scan.is_scan_set = false;
	scan.scan_tech = 5;
	scan.scan_count = 0;
	scan.syn_flag = 'z';
	scan.ack_flag = 'z';
	scan.fin_flag = 'z';
	scan.null_flag = 'z';
	scan.xmas_flag = 'z';
	scan.udp_set = 0;
	scan.scan_type[1] = "Port";
	scan.scan_type[2] = "scanner";
	
	struct params param = *(struct params *)arg;
        scan.evaluate_args(param.count_args , param.arg_para);
	if(scan.ips.size() == 0)
	{
		cout<<"Please enter at least 1 IP Address"<<endl<<endl;
		exit(0);
	}

	if( !scan.is_port_set && scan.ports.size() == 0 )
        {
                while(min_port<=max_port)
                {
                        scan.add_port_to_list(scan.convert_i_to_s(min_port) , &scan.ports);
                	min_port++;
        	}
        }
	std::list<string>::iterator it_port = scan.ports.begin();
	while(it_port != scan.ports.end())
	{
		int temp_port = atoi( (char*)((*it_port).c_str()));
		if(temp_port > 65536)
		{
			cout<<"Port number cannot be greater than 65536"<<endl<<endl;
			exit(0);
		}
		++it_port;
	}	
	
	if(!scan.is_scan_set)
        {
                ack_count = 1;
                syn_count = 0;
                fin_count = 0;
                null_count = 0;
                xmas_count = 0;
        }

	
        char packet[65536];
        memset(packet , 0 , sizeof(packet));
        int sock_to_send;

        struct sockaddr_in send_dest;

        struct iphdr *iph = (struct iphdr *)packet;
        struct tcphdr *tcp = (struct tcphdr *)(packet + sizeof(iphdr));

        struct pseudo_header psh;

        sock_to_send = socket(AF_INET , SOCK_RAW , IPPROTO_TCP);
        if(sock_to_send < 0)
        {
                cout<<"The socket is not created: "<<endl;
                exit(0);
        }
        
		if(scan.scan_count > 0)
			scan.scan_tech = scan.scan_count;

		std::list<string>::iterator it;
		for (it=scan.ips.begin(); it!=scan.ips.end(); ++it)
		{
			cout<<"------"<<*it<<"------"<<endl;
			if(scan.is_scan_set)
			{
				ack_set = scan.ack_flag;
				syn_set = scan.syn_flag;
				fin_set = scan.fin_flag;
				null_set = scan.null_flag;
				xmas_set = scan.xmas_flag;
			}
			scan.ipadr = (char*)((*it).c_str());
                        	/*if( !scan.is_port_set && scan.ports.size() == 0 )
                                {
                                        while(min_port<=max_port)
                                        {
                                                scan.add_port_to_list(scan.convert_i_to_s(min_port) , &scan.ports);
                                                min_port++;
                                        }
                                }*/
			std::list<string>::iterator itr;
                        for(itr = scan.ports.begin();itr!=scan.ports.end();++itr)
                        {
                                        char* temp_port;
                                        char* ch;
                                        memset(&temp_port,0,1);
                                        memset(&ch,0,1);
                                        ch = (char*)((*itr).c_str());
                                        scan.port = strtol(ch , &temp_port , 10);
                                        port_val = scan.port;
	
				for(int c = 0 ; c < scan.scan_tech ; c++)
        			{
	
		                        send_dest.sin_family = AF_INET;
		                        send_dest.sin_port = htons(scan.port);
		                        send_dest.sin_addr.s_addr = inet_addr(scan.ipadr);
					
					iph->ihl = 5;
	                                iph->version = 4;
                                	iph->tos = 0;
                                	iph->ttl = ~0;
                                	iph->tot_len = sizeof(struct iphdr) + sizeof(struct tcphdr);
                                	iph->id = htons(23343);
                                	iph->frag_off = htons(16384);
                                	iph->protocol = IPPROTO_TCP;
                                	iph->check = 0;
                                	iph->saddr = inet_addr((char*)param.own_ip.c_str());
	                                iph->daddr = inet_addr(scan.ipadr);
	                                iph->check = calculate_checksum ((unsigned short *) packet, iph->tot_len >> 1);

        	                        tcp->source = htons(12732);
	                                tcp->seq = htonl(1105024978);
	                                tcp->ack_seq = 0;
	                                tcp->doff = 5;
					tcp->fin=0;
                                        tcp->syn=0;
                                        tcp->rst=0;
                                        tcp->psh=0;
                                        tcp->ack=0;
                                        tcp->urg=0;	

	                                if(scan.is_scan_set)
	                                {
	                                	if(ack_set == 'a')
							tcp->ack=1;
	                                        else if(syn_set == 's')
	                                                tcp->syn=1;
	                                        else if(fin_set == 'f')
	                        			tcp->fin=1;
	                                        else if(null_set == 'n')
	                                     	{
	                                    	}
	                                     	else if(xmas_set == 'x')
	                                   	{
	                                       		tcp->fin=1;
	                                         	tcp->psh=1;
	                                          	tcp->urg=1;
	                                        }
	                         	}
	                                else
        	                    	{
	                                  	if(xmas_count == 1)
	                               		{
                                                        tcp->fin=1;
                                                        tcp->psh=1;
                                                        tcp->urg=1;
                                                }
                                  		if(null_count == 1)
						{}
						if(fin_count == 1)
							tcp->fin = 1;
                                        	if(syn_count == 1)
							tcp->syn = 1;
                                	        if(ack_count == 1)
							tcp->ack = 1;
	                                        
					}
                                
                                        tcp->window = htons ( 14600 );
                                        tcp->check = 0;
					tcp->urg_ptr = 0;
		
					tcp->dest = htons(scan.port); 

		                        psh.src_add = inet_addr((char*)param.own_ip.c_str());
		                        psh.dest_add = send_dest.sin_addr.s_addr;
		                        psh.pl_holder = 0;
		                        psh.proto = IPPROTO_TCP;
		                        psh.tcp_len = htons( sizeof(struct tcphdr) );
	
		                        memcpy(&psh.tcph , tcp , sizeof (struct tcphdr));

		                        tcp->check = calculate_checksum( (unsigned short*) &psh , sizeof (struct pseudo_header));

		                        int a = 1;
		                        const int* value = &a;

		                        if((setsockopt(sock_to_send , IPPROTO_IP , IP_HDRINCL , &value , sizeof(a))) < 0)
		                        {
	        	                        cout<<"Error in setsockopt: "<<errno<<" --- "<<strerror(errno)<<endl;
	                	                exit(0);
		                        }

        		                if((sendto(sock_to_send , packet , sizeof(struct iphdr) + sizeof(struct tcphdr) , 0 , (struct sockaddr *)&send_dest , sizeof(send_dest))) < 0){
                		                cout<<"Error in sendto: "<<errno<<" --- "<<strerror(errno)<<endl;
                        		        exit(0);
	                        	}

					unsigned char* recv_buf_tcp = (unsigned char*)malloc(2048);
					unsigned char* recv_buf_icmp = (unsigned char*)malloc(2048);
		                        int sock_recv_tcp;
					int sock_recv_icmp;
					struct sockaddr recv_dest_tcp;
        				socklen_t length_tcp;
					struct sockaddr recv_dest_icmp;
        				socklen_t length_icmp;

		                        sock_recv_tcp = socket(AF_INET , SOCK_RAW , IPPROTO_TCP);
					sock_recv_icmp = socket(AF_INET , SOCK_RAW , IPPROTO_ICMP);
		                        if(sock_recv_tcp < 0){
	        	                        cout<<"Error in sock_to_recv: "<<errno<<" --- "<<strerror(errno)<<endl;
		                                exit(0);
		                        }
					if(sock_recv_icmp < 0){
                                                cout<<"Error in sock_to_recv: "<<errno<<" --- "<<strerror(errno)<<endl;
                                                exit(0);
                                        }
	        	                length_tcp = sizeof (recv_dest_tcp);
					length_icmp = sizeof (recv_dest_icmp);
				
					struct pollfd sock_scan[2];
        				sock_scan[0].fd = sock_recv_icmp;
        				sock_scan[0].events = POLLIN;
        				sock_scan[1].fd = sock_recv_tcp;
        				sock_scan[1].events = POLLIN;

        				int flag = 0;
        				int wait;
        				wait = poll(sock_scan , 2 , 7000);
        				if(wait == -1)
                				cout<<"Error"<<endl;
        				else if(wait == 0)
                				cout<<"Timeout"<<endl;
        				else
        				{
                				if(sock_scan[0].revents & POLLIN)
                				{
                        				if(recvfrom(sock_recv_icmp , recv_buf_icmp , 2048  , 0 , (struct sockaddr *)&recv_dest_icmp , (socklen_t*)&length_icmp) < 0)
                        				{
                                				cout<<"Error in recvfrom: "<<errno<<" --- "<<strerror(errno)<<endl;
                                				exit(0);
                        				}
                        				else
							{
                                				flag = 1;
							}
                				}
                				if(sock_scan[1].revents & POLLIN)
                				{
                        				if(recvfrom(sock_recv_tcp , recv_buf_tcp , 2048  , 0 , (struct sockaddr *)&recv_dest_tcp , (socklen_t*)&length_tcp) < 0)
                        				{
                                				cout<<"Error in recvfrom: "<<errno<<" --- "<<strerror(errno)<<endl;
                                				exit(0);
                        				}
                				}
        				}
        				if(flag)
                				scan_output(recv_buf_icmp , scan , atoi( (char*)((*itr).c_str()) ));
        				else
			                	scan_output(recv_buf_tcp , scan , atoi( (char*)((*itr).c_str()) ) );
					free(recv_buf_icmp);
        	        	        close(sock_recv_icmp);
					free(recv_buf_tcp);
                                        close(sock_recv_tcp);	

               
				
					if(scan.is_scan_set)
					{	
						if(ack_set == 'a')
							ack_set = 'z';
						else if(syn_set == 's')
							syn_set = 'z';
						else if(fin_set == 'f')
							fin_set = 'z';
						else if(null_set == 'n')
							null_set = 'z';
						else if(xmas_set == 'x')
							xmas_set = 'z';
					}
					else
					{
						if(xmas_count == 1){
							 xmas_count = 0; 
						}
						if(null_count == 1){
							 xmas_count = 1; null_count = 0; 
						}
						if(fin_count == 1){
							 null_count = 1; fin_count = 0; 
						}
						if(syn_count == 1){
							 fin_count = 1; syn_count = 0;
						}
						if(ack_count == 1){
							 syn_count = 1; ack_count = 0;
						}
					}
				} //for loop for scan_tech close	

	                        if(scan.scan_type[1] == "UDP" || !scan.udp_set)
        	                {
                	                start_udp_scan(scan , scan.ipadr , param.own_ip);
                        	}
	                        if(scan.scan_type[2] == "TCP" || scan.scan_tech)
        	                {
                	                print_scan_status(scan , scan.ipadr , atoi( (char*)((*itr).c_str()) ));
                        	        if(!scan.is_scan_set)
                                	        ack_count = 1;
	                        }
        	                if(scan.scan_type[1] == "UDP" || !scan.udp_set)
                	        {
                        	        cout<<"----------UDP----------"<<endl;
	                                print_udp_results(port_udp_scan , scan.ipadr , atoi( (char*)((*itr).c_str()) ));
        	                }
                	        cout<<endl;
                        	print_conclusion(atoi( (char*)((*itr).c_str()) ));
				conclusion.clear();
				std::list<char>::iterator itre = conclusion.begin();
				while(itre != conclusion.end())
				{
					cout<<"---------------------------------------------------------------------"<<*itre<<endl;
					++itre;
				}
				cout<<endl;

				if(!scan.is_scan_set)
					ack_count = 1;
				else
        	                {
                	                ack_set = scan.ack_flag;
                        	        syn_set = scan.syn_flag;
                                	fin_set = scan.fin_flag;
	                                null_set = scan.null_flag;
        	                        xmas_set = scan.xmas_flag;
                	        }
                        
			}//for loop for port closed			

			cout<<endl<<endl;

		} //for loop for ip address closed

}

int main(int argc , char* argv[]){

	cout<<endl;
	time_t starttime = time(NULL);
	
	string ch;
	
	ch = find_own_ip("129.79.247.5" , 22);
	
	add_tcp_services();
	add_udp_services();

	params para;	
	para.count_args = argc;
	para.arg_para = argv;
	para.own_ip = ch;
	
	pthread_t thread_tcp;
	if( pthread_create(&thread_tcp , NULL , start_tcp_scan , &para) )
		cout<<"Error"<<endl;
	pthread_join(thread_tcp,NULL);
	
	time_t endtime = time(NULL);
	//cout << "  Total time :"
		//		<< (double) (endtime - starttime)<<endl;

	return 0;

}


