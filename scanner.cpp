#include <stdio.h>
#include <stdlib.h>
#include <unistd.h>
#include <string.h>
#include <sys/types.h>
#include <sys/socket.h>
#include <netinet/in.h>
#include <netdb.h> 
#include <vector>
#include <iostream>
#include <fstream>
#include <unistd.h>
#include <chrono>
#include <algorithm>
#include <random>
#include<netinet/tcp.h> 
#include<netinet/ip.h> 
#include <arpa/inet.h>

void error(const char *msg)
{
    perror(msg);
}

struct pseudo_header
{
    u_int32_t source_address;
    u_int32_t dest_address;
    u_int8_t placeholder;
    u_int8_t protocol;
    u_int16_t tcp_length;
};
 
/*
    Generic checksum calculation function
*/
unsigned short csum(unsigned short *ptr,int nbytes) 
{
    register long sum;
    unsigned short oddbyte;
    register short answer;
 
    sum=0;
    while(nbytes>1) {
        sum+=*ptr++;
        nbytes-=2;
    }
    if(nbytes==1) {
        oddbyte=0;
        *((u_char*)&oddbyte)=*(u_char*)ptr;
        sum+=oddbyte;
    }
 
    sum = (sum>>16)+(sum & 0xffff);
    sum = sum + (sum>>16);
    answer=(short)~sum;
     
    return(answer);
}

std::vector<std::string> getPorts(std::string s)
{
	/*****************************GET PORTS*******************************/
	std::vector<std::string> ports;
	std::string portFile = s;

	std::ifstream inPorts(portFile.c_str());
	std::string tmpLine;
 
	// Check if object is valid
	if(!inPorts)
	{
		std::cerr << "Cannot open the File : "<<portFile<<std::endl;
		exit(1);
	}
 
	
	// Read the next line from File untill it reaches the end.
	while (std::getline(inPorts, tmpLine))
	{
		// Line contains string of length > 0 then save it in vector
		if(tmpLine.size() > 0)
			ports.push_back(tmpLine);
	}
	//Close The File
	inPorts.close();
		
	//shuffle the vector so the ports will be tested in random order
	unsigned seed = std::chrono::system_clock::now().time_since_epoch().count();
	std::default_random_engine rng (seed);
	std::shuffle(ports.begin(), ports.end(), rng);
    return ports;
}

std::vector<std::string> getHosts(std::string s)
{
	/*******************************GET HOSTS*******************************/

	std::vector<std::string> hosts;
	std::string hostFile = s;

	std::ifstream inHosts(hostFile.c_str());
	std::string tmpLine;
 
	// Check if object is valid
	if(!inHosts)
	{
		std::cerr << "Cannot open the File : "<<hostFile<<std::endl;
		exit(1);
	}
 
	// Read the next line from File untill it reaches the end.
	while (std::getline(inHosts, tmpLine))
	{
		// Line contains string of length > 0 then save it in vector
		if(tmpLine.size() > 0)
			hosts.push_back(tmpLine);
	}
	//Close The File
	inHosts.close();
    return hosts;
}

void createIp(iphdr *iph, char *source_ip, sockaddr_in &sin, char *datagram)
{
	iph->ihl = 5;
    iph->version = 4;
    iph->tos = 0;
    iph->tot_len = sizeof (struct iphdr) + sizeof (struct tcphdr);
    iph->id = htonl (54321); //Id of this packet
    iph->frag_off = 0;
    iph->ttl = 255;
    iph->protocol = IPPROTO_TCP;
    iph->check = 0;      //Set to 0 before calculating checksum
    iph->saddr = inet_addr ( source_ip );    //Spoof the source ip address
    iph->daddr = sin.sin_addr.s_addr;
     
    //Ip checksum
    iph->check = csum ((unsigned short *) datagram, iph->tot_len);
}

void createTcp(tcphdr *tcph)
{
	//TCP Header
    tcph->source = htons (1234);
    tcph->dest = htons (3000);
    tcph->seq = 0;
    tcph->ack_seq = 0;
    tcph->doff = 5;  //tcp header size
    tcph->fin=0;
    tcph->syn=1;
    tcph->rst=0;
    tcph->psh=0;
    tcph->ack=0;
    tcph->urg=0;
    tcph->window = htons (5840); /* maximum allowed window size */
    tcph->check = 0; //leave checksum 0 now, filled later by pseudo header
    tcph->urg_ptr = 0;
}

void scan()
{
	/*******************************CREATE IP Header**************************/	

    //Create a raw socket
    int write_socket = socket (PF_INET, SOCK_RAW, IPPROTO_TCP);
    int read_socket = socket(AF_INET, SOCK_RAW, IPPROTO_TCP);   
    
    if(write_socket == -1 || read_socket == -1)
    {
        error("Failed to create socket");
    }
     
    //Datagram to represent the packet
    char datagram[4096] , source_ip[32], *pseudogram;
     
    //zero out the packet buffer
    memset (datagram, 0, 4096);
     
    //IP header
    struct iphdr *iph = (struct iphdr *) datagram;
     
    //TCP header
    struct tcphdr *tcph = (struct tcphdr *) (datagram + sizeof (struct ip));
    struct sockaddr_in sin;
    struct pseudo_header psh;
     
    //some address resolution
    strcpy(source_ip , "10.2.26.219");
    sin.sin_family = AF_INET;
    sin.sin_port = htons(3000);
    sin.sin_addr.s_addr = inet_addr ("45.33.32.156");
     
    //Fill in the IP and TCP Header
    createIp(iph, source_ip, sin, datagram);
    createTcp(tcph);
  
    //Now the TCP checksum
    psh.source_address = inet_addr( source_ip );
    psh.dest_address = sin.sin_addr.s_addr;
    psh.placeholder = 0;
    psh.protocol = IPPROTO_TCP;
    psh.tcp_length = htons(sizeof(struct tcphdr));
     
    int psize = sizeof(struct pseudo_header) + sizeof(struct tcphdr);
    pseudogram = (char*)malloc(psize);
     
    memcpy(pseudogram , (char*) &psh , sizeof (struct pseudo_header));
    memcpy(pseudogram + sizeof(struct pseudo_header) , tcph , sizeof(struct tcphdr));
     
    tcph->check = csum( (unsigned short*) pseudogram , psize);
     
    //IP_HDRINCL to tell the kernel that headers are included in the packet
    int one = 1;
    const int *val = &one;
     
    if (setsockopt (write_socket, IPPROTO_IP, IP_HDRINCL, val, sizeof (one)) < 0)
    {
        error("Error setting IP_HDRINCL");
    }
     
    //Send the packet
    if (sendto (write_socket, datagram, iph->tot_len ,  0, (struct sockaddr *) &sin, sizeof (sin)) < 0)
    {
        error("sendto failed");
    }
    else
    {
        printf ("Packet Send. Length : %d \n" , iph->tot_len);
    }

    char read_buffer[2000];
    ssize_t received_bytes;
    usleep(10);
    socklen_t dsize = sizeof(sin);
    received_bytes=recv(read_socket, read_buffer , sizeof(read_buffer), 0);
    iphdr* read_iphdr = (iphdr*) read_buffer;
   
    tcphdr* read_tcphdr = (tcphdr*)(read_buffer + (int)read_iphdr->ihl*4); 

    if( received_bytes < 0 )
    {
            error("\n\t recv() error \n");
    }

    if(tcph->syn==1)
    {
    	if (read_tcphdr->syn==1)
    	{
    		printf("syn open\n");
    	}
    	else
    	{
    		printf("syn closed\n");
    	}
    }
    else if(tcph->fin==1)
    {
    	
    	if (read_tcphdr->rst==1)
    	{
    		printf("fin closed\n");
    	}
    	else
    	{
    		printf("fin OPEN|FILTERED\n");
    	}
    }
    //if null flag
    else
    {
    	if (read_tcphdr->rst==1)
    	{
    		printf("null closed\n");
    	}
    	else
    	{
    		printf("null OPEN|FILTERED\n");
    	}
    }

    close(write_socket);
    close(write_socket);

    double f = (double)rand() / RAND_MAX;
    sleep(0.5 + f);

}

int main(int argc, char *argv[])
{
    if (argc < 5) {
       fprintf(stderr,"usage %s your ip address, hosts.txt, portst.txt, flag(S = syn, F = fin, N = null, X = xmas)\n", argv[0]);
       exit(0);
    }

    std::string hostsFile = argv[2];
    std::string portsFile = argv[3];
    std::string flag = argv[4];
    std::vector<std::string> hosts = getHosts(hostsFile);
    std::vector<std::string> Ports = getPorts(portsFile);

    

	scan();

    return 0;
}
