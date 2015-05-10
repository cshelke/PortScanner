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

unsigned short calculate_checksum(unsigned short *hdr , int len)
{
        register long final;
        unsigned short pad = 0;
        register short answer;

        final=0;
        while(len>1)
        {
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

        while (final>>16)
                final = (final & 0xFFFF)+(final >> 16);

        //cout<<"by new method-> final : "<<(short)~final<<endl;
        return((short)~final);

}


char* find_own_ip(string str, int x)
{

        char* buffer;
        int ip_sock = socket ( AF_INET, SOCK_STREAM, 0);

        if(ip_sock < 0)
                cout<<"Error creating socket"<<endl;

        const char* rand_ip = (char*)str.c_str();
        int rand_port = x;

        struct sockaddr_in server , ip_own;

        memset( &server, 0, sizeof(server) );
        server.sin_family = AF_INET;
        server.sin_addr.s_addr = inet_addr(rand_ip);
        server.sin_port = htons( rand_port );

        if( (connect( ip_sock , (const struct sockaddr*) &server , sizeof(server) )) < 0)
                cout<<"Error connecting"<<endl;

        socklen_t ip_own_len = sizeof(ip_own);
        getsockname(ip_sock, (struct sockaddr*) &ip_own, &ip_own_len);

        //const char *p = inet_ntop(AF_INET, &ip_own.sin_addr, buffer, 100);;
        close(ip_sock);
        return inet_ntoa(ip_own.sin_addr);
}



