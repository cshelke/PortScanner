#include<iostream>
#include<string.h>
#include<cstdio>
#include<cstring>
#include<stdlib.h>
#include<cstdlib>
#include<cstdio>
#include<sstream>
#include<cctype>
#include<math.h>
#include<list>
#include<fstream>
using namespace std;

int arr[8];
int temp[8];
int rand_bits, MAX_VAL;
string first_half_ip,ip;
string secnd_half_ip;
//list <string> ips;

class Prefix{
	public:
	list <string> ips;
	list <string> ports;
	list<string> s_type;
	map <int , string> scan_type;
	char* ipadr;
	short port;
	bool is_port_set;
	bool is_scan_set;
	int scan_tech;
	int scan_count;
	char syn_flag;
	char ack_flag;
	char fin_flag;
	char null_flag;
	char xmas_flag;
	int udp_set;
	int arg_flag;
	int speedup;

	void add_to_list(string , list<string>*);
	void add_port_to_list(string , list<string>*);
	void add_scan_type_to_list(string , list<string>*);
	void print_list(list<string> *);
	string convert_i_to_s(int);
	void conv_dec_bin(int ,int);
	void calc_positions(string );
	void manipulate_prefix();
	void print_file(string);
	void evaluate_args(int , char**);
	void find_dash_position(string);

}pre;

void Prefix :: add_to_list(string ip_to_add, list<string> *temp)
{
	temp->push_back(ip_to_add);
}

void Prefix :: add_port_to_list(string port_to_add, list<string> *temp)
{
        temp->push_back(port_to_add);
}

void Prefix :: add_scan_type_to_list(string type, list<string> *temp)
{
        temp->push_back(type);
}


void Prefix :: find_dash_position(string temp1)
{

	int x = 0;
        int pos_dash = 0;
        while(temp1[x]!='-')
        	x++;
        pos_dash = x;
        int min = atoi((char*)(temp1.substr(0,pos_dash)).c_str());
        int max = atoi((char*)(temp1.substr((pos_dash+1) , (strlen((char*)temp1.c_str())-pos_dash+1))).c_str());
        while(min<=max)
        {
        	add_port_to_list(convert_i_to_s(min) , &ports);
                min++;
        }

}

void Prefix :: print_list(list<string> *temp)
{

	cout<<endl<<"The final list is:"<<endl;
	std::list<string>::iterator it;

	for (it=temp->begin(); it!=temp->end(); ++it){
		cout<<*it<<endl;
	}
}


string Prefix :: convert_i_to_s(int x){
	
	string str1;
	str1.clear();
        stringstream i_to_s;
        i_to_s << x;
        str1 = i_to_s.str();
	return str1;
}


void Prefix :: conv_dec_bin(int part,int b){
	int j;
	int i = b;
	//find the binary representation of the integer
	while(part>0)
        {
                temp[i] = part%2;
                part = part/2;
                i++;
        }
	//add the remaining bits to make the binary a 8 bit binary representation
        for(j = i ; j<8;j++)
                temp[j] = 0;
	i = b;
	//finally copy the whole calculated binary into another array
        for(j = j-1 ; j>=0 ; j--)
        {
                arr[i] = temp[j];
                i++;
        }

}

void Prefix :: calc_positions(string str1){

	int pos,i,prefix;
	int j = 0;
	string value;
	pos = str1.find("/");

        for(i=pos+1 ; i<strlen(str1.c_str()) ; i++)
        {
                value[j] = str1[i];
                j++;
        }
        j = 0;
        for(i = pos ; str1[i]!='.' ; i--)
                j = i;

        prefix = atoi(value.c_str());
        if(prefix > 31)
        	{
        		cout<<"Invalid arguments! "<<endl;
        		exit(0);
        	}

        first_half_ip = str1.substr(0,j);

        secnd_half_ip = str1.substr(j,(pos-j));

        rand_bits = 32 - prefix;

}

void Prefix :: print_file(string infile){

	string line = "";
	ifstream file_toread((char*)infile.c_str());
	if(file_toread.is_open())
	{
		while(getline(file_toread,line))
			add_to_list(line,&ips);
	}
}

void Prefix :: manipulate_prefix()
{
	int last_ip_part,x,a,j,i;
	last_ip_part = atoi(secnd_half_ip.c_str());

		if(rand_bits == 0){
			cout<<first_half_ip+secnd_half_ip<<endl;
			exit(1);
		}


		conv_dec_bin(last_ip_part,0);

		MAX_VAL = pow(2,rand_bits);

		for(a = 0 ; a < MAX_VAL ; a++){

			x = a;
			int dec = 0;
			conv_dec_bin(x,8-rand_bits);

			//convert the binary to decimal
	                j = 0;
	                for(i = 7 ; i>=0 ; i--){
	                	dec = dec + arr[i]*pow(2,j);
	                        j++;
	                }
			//convert the integer decimal to string decimal
	                ip = convert_i_to_s(dec);
			//concatenate the ip addresses
	                ip = first_half_ip + ip;
	               	add_to_list(ip,&ips);

		}
}

void Prefix::evaluate_args(int argc, char* argv[]) {

	string str1;
	string infile;
	string given_ip;
	bool ip_flag = false;
	int i = 1;
	memset(&temp, 0, 8);
	memset(&arr, 0, 8);
	speedup = 1;
	if (argc == 1) {
		cout << "Please enter command line arguments" << endl<<endl;
		exit(1);
	}
	
	while(i<argc){
		
		if (strcmp(argv[i], "--prefix") == 0) {
			ip_flag = true;
			int dot_count = 0;
			str1 = argv[i + 1];
			for(int j = 0 ; j < strlen((char*) str1.c_str()); j++) {
			if (((char*) str1.c_str())[j] == '.')
				dot_count++;
			}
			if(dot_count < 3 || dot_count > 3)
			{
				cout<<"Invalid arguments! "<<endl<<endl;
				exit(0);
			}
			calc_positions(str1);
			manipulate_prefix();
			i = i+2;
		} else if (strcmp(argv[i], "--file") == 0) {
			ip_flag = true;
			infile = argv[i + 1];
			print_file(infile);
			i = i+2;
		}else if (strcmp(argv[i], "--ip") == 0) {
			ip_flag = true;
			int dot_count = 0;
			given_ip = argv[i + 1];
			if(given_ip.find("/")!=-1)
			{
				cout<<"Invalid arguments! "<<endl<<endl;
						exit(0);
			}
			for(int j = 0 ; j < strlen((char*) given_ip.c_str()); j++) {
				if (((char*) given_ip.c_str())[j] == '.')
					dot_count++;
			}
			if(dot_count < 3 || dot_count > 3)
			{
				cout<<"Invalid arguments! "<<endl<<endl;
				exit(0);
			}
			char* ch = strtok((char*)given_ip.c_str() , ".");
			while (ch != NULL) {
				string temp_ip = ch;
				if (atoi((char*) temp_ip.c_str()) > 255) {
					cout << "Invalid arguments! "
							<< endl << endl;
					temp_ip.clear();
					exit(0);
				}
				ch = strtok(NULL, ".");
				temp_ip.clear();
			}
			add_to_list(argv[i+1], &ips);
			i = i+2;
		}else if (strcmp(argv[i], "--port") == 0) {

			is_port_set = true;
			std::string value(argv[i + 1]);
			int count = 0;
			if (strlen((char*) value.c_str()) > 2) {
				if ((value.find(",") == -1) && (value.find("-") != -1))
					find_dash_position(value);
				else {
					for (int j = 0; j < strlen((char*) value.c_str()); j++) {
						if (((char*) value.c_str())[j] == ',')
							count++;
					}
					for (int j = 0; j < count; j++) {
						string temp1;
						temp1.clear();
						std::size_t pos = value.find(",");
						temp1 = value.substr(0, pos);
						if (temp1.find("-") != -1) {
							find_dash_position(temp1);
						} else
							add_port_to_list(temp1, &ports);

						value = value.substr(pos + 1,
								(strlen((char*) value.c_str()) - (pos + 1)));
					}
					if (value.find("-") != -1)
						find_dash_position(value);
					else
						add_port_to_list(value, &ports);
				}
			} else
				add_port_to_list(value, &ports);
			i=i+2;
		} else if (strcmp(argv[i], "--scan") == 0) {
			int j;
			string diff_scan = "";
			int m = i+1;
			while(true)
			{
				if(m==(argc) || (strcmp(argv[m], "--prefix") == 0) ||
						(strcmp(argv[m], "--ip") == 0) ||
						 (strcmp(argv[m], "--help") == 0) ||
                        (strcmp(argv[m], "--speedup") == 0) ||
						(strcmp(argv[m], "--file") == 0) ||
						(strcmp(argv[m], "--port") == 0))
					break;

				else{
					m++;}
			}

			int k=i+1;
			while(k<m)
			{
				if ((strcmp(argv[k], "SYN") == 0)
						|| (strcmp(argv[k], "ACK") == 0)
						|| (strcmp(argv[k], "FIN") == 0)
						|| (strcmp(argv[k], "NULL") == 0)
						|| (strcmp(argv[k], "Xmas") == 0)
						|| (strcmp(argv[k], "UDP") == 0))
				{
					std::string app(argv[k]);
					diff_scan = diff_scan + "," + app;
					app.clear();
					k++;
				}
				else
				{
					cout<<"Invalid arguments !!"<<endl<<endl;
					exit(0);
				}
			}
			is_scan_set = true;
			std::string scan_values(argv[i + 1]);

			if ((strlen((char*) scan_values.c_str()) == 3)
					&& (scan_values.find("UDP") != -1)) {
				scan_type[1] = "UDP";
				udp_set = 1;
			}

			else if ((strlen((char*) diff_scan.c_str()) >= 3)
					&& (diff_scan.find("UDP") == -1)) {
				udp_set = 1;
				scan_type[2] = "TCP";

				if (diff_scan.find("SYN") != -1) {
					syn_flag = 's';
					scan_count++;
					add_scan_type_to_list("SYN",&s_type);
				}
				if (diff_scan.find("ACK") != -1) {
					ack_flag = 'a';
					scan_count++;
					add_scan_type_to_list("ACK",&s_type);
				}
				if (diff_scan.find("NULL") != -1) {
					null_flag = 'n';
					scan_count++;
					add_scan_type_to_list("NULL",&s_type);
				}
				if (diff_scan.find("FIN") != -1) {
					fin_flag = 'f';
					scan_count++;
					add_scan_type_to_list("FIN",&s_type);
				}
				if (diff_scan.find("Xmas") != -1) {
					xmas_flag = 'x';
					scan_count++;
					add_scan_type_to_list("Xmas",&s_type);
				}
			} else if ((strlen((char*) diff_scan.c_str()) > 4)
					&& (diff_scan.find("UDP") != -1)) {
				scan_type[1] = "UDP";
				scan_type[2] = "TCP";
				udp_set = 1;

				if (diff_scan.find("SYN") != -1) {
					syn_flag = 's';
					scan_count++;
					add_scan_type_to_list("SYN",&s_type);

				}
				if (diff_scan.find("ACK") != -1) {
					ack_flag = 'a';
					scan_count++;
					add_scan_type_to_list("ACK",&s_type);
				}
				if (diff_scan.find("NULL") != -1) {
					null_flag = 'n';
					scan_count++;
					add_scan_type_to_list("NULL",&s_type);
				}
				if (diff_scan.find("FIN") != -1) {
					fin_flag = 'f';
					scan_count++;
					add_scan_type_to_list("FIN",&s_type);
				}
				if (diff_scan.find("Xmas") != -1) {
					xmas_flag = 'x';
					scan_count++;
					add_scan_type_to_list("Xmas",&s_type);
				}

			}
			i=m;
		}
		else if(strcmp(argv[i], "--speedup") == 0)
		{
			speedup = atoi(argv[i + 1]);
			i = i+2;
		}

		else if (strcmp(argv[i], "--help") == 0) {
			cout << endl
					<< "The following project deals with the implementation of\n"
							"PortScanner where for a given IP address and list of\n"
							"port number the various TCP and UDP ports are scanned\n"
							"The result of the scanner infers about the porrt status\n"
							"1. Open\n"
							"2. Closed\n"
							"3. Filtered\n"
							"4. Open|Filtered\n"
							"The port scanner also checks if the services like Http,\n"
							"SSH etc are functionsl when the respective ports are\n"
							"scanned.\n"
							"Include any of the cmd line arguments while execution\n\n"
							"1. --ip/--prefix/--file to give the ip address\n"
							"2. --port to enter the port numbers to scan\n"
							"3. --scan to scan particular TCP flags\n"
							"4. --speedup to execute multiple threads\n"
					<< endl;
			exit(0);
		}
		else
		 {
		 cout<<"Please enter valid arguments"<<endl<<endl;
		 exit(0);
		 }
	}

	if(!ip_flag)
	{
		cout<<"Invalid arguments! "<<endl<<endl;
		exit(0);
	}

}


