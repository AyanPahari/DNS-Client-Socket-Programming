# DNS Client Socket Programming

Implemented a standard UDP based DNS client. This client takes a url from the user and returns it’s IPV4 address along with some other fields such as the class, type and time to live information as received from the server. Created a standard DNS packet by appending all the required headers and sent the request to standard DNS server (on port#53), then parsed the results sent by the server and displayed the required information.
## Instructions on running the program

Platform Used : Linux with GCC

Compiling the Codes : 
    
    gcc dnsClient.c

Running the Client: 

    ./a.out domain_name

- Ctrl+C to be used for stopping the DNS Client
- Provide the domain_name for which you want to see the IP address.
## Screenshots

![Output Screenshot](https://github.com/AyanPahari/DNS-Client-Socket-Programming/blob/master/output.JPG)

