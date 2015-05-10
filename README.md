# PortScanner
============
Code Description:
============
Port Scanner is an application which is vastly employed by the network administrators and advesaries
to scan aprticular port on any ip address to find out and monitor the service running on that particular 
port. The tool nmap is popular among the network geeks to scan any port on an ip address.
Our project Port Scanner is an honest effort to replicate the tool nmap to a certain extent.

The project has 2 different versions:
1. Single Threaded version.
2. Multi Threaded version.

=================
Single Threaded Version:
=================
a.) The single threaded version contains a single thread. Based on the parameters given by the user 
     the thread executes the TCP and UDP scans.
b.) The inputs can be such that the user can mention/not mention - the port numbers, scan types but
      has to pass the ip address to scan.
c.) If the user does not passes the port number and scan types then the code will perform all TCP and 
     UDP scans on ports ranging from 1-1024.
d.) A for loop for all the ip addresses in the list is iterated. Inside the for loop another for loop for all the 
     ports is iterated and another for loop for types of scan is iterated inside it.
e.) For a particular port all the scan types are implemented and the result is added to a hash map after
     each scan type. Finally when the for loop for scan type is finished the map containing the results is
     printed. 
f.) A method is called which then prints the service offered by that particular port. The service version for
    that particular port is also shown if the port is int the range 1-1024.
g.) A conclusion is made on the basis of all scan type results.
h.) The loop for port is increemented and another scan startrs for the next port in the list.
i.) After all the port in that particular ip is scanned, the ip loop iterator has a new ip address to scan with
     the same ports and scan type.

================
Multi Threaded Version:
================
a.) We have a job queue which has the attributes of the ip address, port and scan type. We collect this 
      information from the arguments passed. While sending the jobs, we first pop each job from the jobs
     queue and check if the ip and port is matching with any job in the active queue. If it does not match 
     then we add the job to the active jobs queue and send it to do the corresponding scan. If the ip and 
     port do match from a job already in the active jobs queue, we don't send this job for scanning and 
     don't add it to the active jobs queue. We push back this job again to the jobs queue.
b.) We have a separate thread running which takes care of the reception of the responses. And on the
     basis of the flags from the recieved packets, we conclude about the status of the corresponding ip-port.
c.) There is a separate thread which checks if any job has been in the active jobs queue for more than or 
     equal to 5 seconds. If it has been, then we delete that job from the queue and make a decisions about 
     the ip and port it was scaning. We record this status in maps according to the ip and ports.
d.)We have applied mutexes on needed shared variables viz, jobs and the active jobs queue to avoid deadlock 
     and have used sleep() efficiently in required places to get the maximum throughput.

==============
Tasks Accomplished:
============== 
1. Successfully implemented all the requirements specified in the pdf for single threaded version.
2. Successfully able to sppedup the output using the multithreaded speedup version.
3. Succesfully concluded the service version for a list of IP Addresses.

======
Compile:
======
Compile using th makefile provided.

Enter the command "make" to compile both the singlethreaded and multithreaded file. The output files ps_single 
and ps_multi are created respectively for singlethreaded and multithreaded file.
======
Execute:
======
To execute the client and server various commands can be given depending upon the options the user wants
Following are the 2 test conditions for each client and server

To execute : In Blondie Server

For singlethreaded: sudo nice ./ps_single --ip 129.79.247.87 --port 22 --scan SYN
For multithreaded:  sudo nice ./ps_multi --ip 129.79.247.87 --port 22 --scan SYN

======
Interpret
======
For SYN – The result should be open if port is open else closed and filtered if no response.
For ACK – The result should be unfiltered for open/closed ports & filtered if no response.
For FIN – The result should be closed for closed port & open|filtered for no response & filtered for ICMP 
	unreachable errors.
For NULL – The result should be closed for closed port & open|filtered for no response & filtered for ICMP 
	unreachable errors.
For Xmas – The result should be closed for closed port & open|filtered for no response & filtered for ICMP 
	unreachable errors.
For UDP - The result should be closed if ICMP unreachable error is shown with type - 3 and code - 3 else 
	open|filtered for other code values and open if a UDP response is received.
