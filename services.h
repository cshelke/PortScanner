#include<iostream>
#include<string.h>
#include<map>
#include<stdlib.h>
#include<fstream>

using namespace std;

map<int,string> port_tcp_service;
map<int,string> port_udp_service;


void add_tcp_services()
{
	string line = "";
	int i = 1;
	ifstream file_tcp("file_tcp_services.txt");
	if(file_tcp.is_open())
	{
		while(getline(file_tcp,line))
		{
			port_tcp_service[i] = line;
			i++;
		}            
	}

}

void add_udp_services()
{
	string line = "";
	int i = 1;
	ifstream file_udp("file_udp_services.txt");
	if(file_udp.is_open())
	{
		while(getline(file_udp,line))
		{
			port_udp_service[i] = line;
			i++;
		}            
	}

}
