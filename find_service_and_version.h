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

using namespace std;

void port_service_version(char* server_ip , int port)
{
        struct sockaddr_in serv;
        memset(&serv , 0 , sizeof(serv));
        serv.sin_addr.s_addr = inet_addr(server_ip);
        serv.sin_port = htons(port);
        serv.sin_family = AF_INET;
        int sock = socket(AF_INET , SOCK_STREAM , IPPROTO_TCP);
        if(sock<0)
                cout<<"Error creating socket"<<endl;
        if( connect(sock , (struct sockaddr *) &serv, sizeof(serv)) < 0 )
        {
                cout<<" : Unable to connect "<<endl;
        }
        else
        {
                if(port == 22)
                {
                        char response[1024];
                        memset( response , 0 , sizeof(response) );
                        if ( recv(sock , response , 200 , 0) > 0 )
                                cout<<" : "<<response;
                        else
                        	cout<<" : Foreign host closed!"<<endl;
                }
                else if(port == 43)
                {
                        const char* request;
                        memset(&request , 0 , sizeof(request));
                        request = "www.soic.indiana.edu\r\n";
                        send(sock , request , strlen(request) , 0);
                        char response[1024];
                        char* whois_resp;
                        memset( response , 0 , sizeof(response) );
                        if ( recv(sock , response , 1024 , 0) > 0 )
                        {
                                string whois(response);
                                int pos = whois.find("Version");
                                if(pos != -1)
                                {
                                        pos = pos + strlen("Version") + 1;
                                        cout<<" : "<<whois.substr(pos , 5)<<endl;
                                }
                                else
                                        cout<<" : Unknown service version"<<endl;
                        }
                }
                else if(port == 24 || port == 25 || port == 587)
                {
                        char response[1024];
                        memset( response , 0 , sizeof(response) );
                        if ( recv(sock , response , 1024 , 0) > 0 )
                        {
                                string smtp(response);
                                int pos = smtp.find("220");
                                if(pos != -1 && strcmp(server_ip,"129.79.247.87") == 0)
                                {
                                        pos = pos + strlen("220") + 1;
                                        cout<<" : "<<smtp.substr(pos , 47)<<endl;
                                }
                                else
                                        cout<<" : ESMTP"<<endl;
                        }
                }
                else if(port == 80)
                {
                        const char* request;
                        memset(&request , 0 , sizeof(request));
                        request = "GET / HTTP/1.1\n\n";
                        send(sock , request , strlen(request) , 0);
                        char response[1024];
                        memset( response , 0 , sizeof(response) );
                        if ( recv(sock , response , 1024 , 0) > 0 )
                        {
                                string http(response);
                                if( strcmp(server_ip , "129.79.247.87") == 0 ){
                                        int pos = http.find("<address>");

                                        if(pos != -1)
                                        {
                                                pos = pos + strlen("<address>");
                                                cout<<" : "<<http.substr(pos , 24)<<endl;

                                        }
                                        else
                                                cout<<" : Unknown service version"<<endl;
                                }
                        }
                }
                else if(port == 110)
                {

                        char response[1024];
                        memset( response , 0 , sizeof(response) );
                        if ( recv(sock , response , 1024 , 0) > 0 )
                        {
                                string pop3(response);
                                int pos = pop3.find("+OK");
                                if(pos != -1 && strcmp(server_ip,"129.79.247.87") == 0)
                                {
                                        cout<<" : Dovecot"<<endl;
                                }
                                else
                                        cout<<" : Unknown Service Version"<<endl;
                        }
                }
                else if(port == 143)
                {

                        char response[1024];
                        memset( response , 0 , sizeof(response) );
                        if ( recv(sock , response , 1024 , 0) > 0 )
                        {
                                string imap(response);
                                int pos = imap.find("IMAP");
                                if(pos != -1 && strcmp(server_ip,"129.79.247.87") == 0)
                                {
                                        cout<<" : "<<imap.substr(pos , strlen("IMAP4rev1"))<<endl;
                                }
                                else
                                        cout<<" : Unknown service version"<<endl;
                        }
                }
        }
}


void service_version(int x , char* ip)
{
        switch(x)
        {
                case 22:
                {
                        port_service_version(ip , 22);
                        break;
                }
                case 43:
                {
                        port_service_version(ip , 43);
                        break;
                }
                case 24:
                {
                        port_service_version(ip , 24);
                        break;
                }
                case 25:
                {
                        port_service_version(ip , 25);
                        break;
                }
                case 587:
                {
                        port_service_version(ip , 587);
                        break;
                }
                case 80:
                {
                        port_service_version(ip , 80);
                        break;
                }
                case 110:
                {
                        port_service_version(ip , 110);
                        break;
                }
                case 143:
                {
                        port_service_version(ip , 143);
                        break;
                }
                default:
                {
                        cout<<" : Service version not required"<<endl;
                        break;
                }
        }
}


