/*for (int x = 0; x < hosts.size(); ++x)
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
		    }*/


/********************WAIT TIME******************************************/
		    close(sockfd);
		    double f = (double)rand() / RAND_MAX;
	    	sleep(0.5 + f);
		}
	}