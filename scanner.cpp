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

void error(const char *msg)
{
    perror(msg);
}

int main(int argc, char *argv[])
{

	if (argc < 1) {
   		fprintf(stderr,"usage %s hostname\n", argv[0]);
    	exit(0);
	}

/*****************************GET PORTS*******************************/
	std::vector<std::string> ports;
	std::string portFile = "ports.txt";

	std::ifstream inPorts(portFile.c_str());
	std::string tmpLine;
 
	// Check if object is valid
	if(!inPorts)
	{
		std::cerr << "Cannot open the File : "<<portFile<<std::endl;
		return false;
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

/*******************************GET Clients*******************************/

	std::vector<std::string> hosts;
	std::string hostFile = "hosts.txt";

	std::ifstream inHosts(hostFile.c_str());
 
	// Check if object is valid
	if(!inHosts)
	{
		std::cerr << "Cannot open the File : "<<hostFile<<std::endl;
		return false;
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



/*******************************START SCAN*********************************/	

	for (int x = 0; x < hosts.size(); ++x)
	{
		printf("HOST: %s \n", hosts[x].c_str());
		for (int i = 0; i < ports.size(); ++i)
		{
			int sockfd, portno, n;
	    	struct sockaddr_in serv_addr;           // Socket address structure
		    struct hostent *server;

		    char buffer[256];
		    

		    portno = stoi(ports[i]);     // Read Port No from command line

		    sockfd = socket(AF_INET, SOCK_STREAM, 0); // Open Socket

		    if (sockfd < 0) 
		        error("ERROR opening socket");

		    server = gethostbyname(hosts[x].c_str());        // Get host from IP

		    if (server == NULL) {
		        fprintf(stderr,"ERROR, no such host\n");
		        exit(0);
		    }

		    bzero((char *) &serv_addr, sizeof(serv_addr));

		    serv_addr.sin_family = AF_INET; // This is always set to AF_INET

		    // Host address is stored in network byte order
		    bcopy((char *)server->h_addr, 
		         (char *)&serv_addr.sin_addr.s_addr,
		         server->h_length);

		    serv_addr.sin_port = htons(portno);

		    if (connect(sockfd,(struct sockaddr *) &serv_addr,sizeof(serv_addr)) < 0)
		    { 
		        printf("port %i is closed\n", portno);
		    }
		    else 
		    {
		    	printf("port %i is open\n", portno);
		    }


/********************WAIT TIME******************************************/
		    close(sockfd);
		    double f = (double)rand() / RAND_MAX;
	    	sleep(0.5 + f);
		}
	}
    
    return 0;
}
