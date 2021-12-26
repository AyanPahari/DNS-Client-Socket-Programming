//all the required header files that we will be needing
#include <arpa/inet.h>
#include <inttypes.h>
#include <netdb.h>
#include <netinet/in.h>
#include <stdint.h>
#include <stdio.h>
#include <stdint.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>

struct __attribute__((packed)) record_info{ //structure of a standard dns answer for IPV4 format, here packed is important otherwise compiler will reorder the fields
  unsigned short comps; //compression
  unsigned short type; //type of dns
  unsigned short class; //class of dns 
  int time_to_live; //time to live 
  unsigned short length; //length of the record
  struct in_addr addr;
};

struct question_info{ //structure of a standard dns question
  char* name; //pointer to modified domain name without the dots
  unsigned short type_of_dns; //type of dns
  unsigned short class_of_dns; //class of dns
};

struct header_info{ //structure of a standard dns header
  unsigned short random_id; //random identifier
  unsigned short flags; //bit mask to represent whether it's a request or response
  unsigned short num_of_ques; //number of dns_ques
  unsigned short num_of_ans; //number of answers
  unsigned short num_of_auth; //number of authority recorded_data that are present
  unsigned short num_of_addi; //number of additional recorded_data we will be dealing with
};

unsigned char* append_packet (char *domain_name, int *len){ //we are going to set up the dns header

  struct question_info question; //setting up the structure of the dns question format
  question.type_of_dns = htons (1);  //1 here means type A
  question.class_of_dns = htons (1); //1 here means class IN

  struct header_info dns_header; //declaring a struct header of type header_info
  memset (&dns_header, 0, sizeof (struct header_info)); //clearing any garbage data that was present beforehand
  dns_header.random_id= htons (0x7157);    //randomly chosen ID
  dns_header.flags = htons (0x0100); // Q=0 and RD=1 
  dns_header.num_of_ques = htons (1); //we are sending only one question

  char *name = calloc (strlen (domain_name) + 2, sizeof (unsigned char)); //initializes the region that name points to to all 0's 

  strcpy (name + 1, domain_name); //leaving the first byte blank for the first length filed as per the RFC
  unsigned char count = 0; //to count to length of the various parts of the domain name
  unsigned char *prev = (unsigned char *)name; //maintains a pointer just prev to the current pointer
  for (int k = 0; k < strlen(domain_name); k++){ //this loop is replacing every instance of '.' with the length of the domain part behind it
      if (domain_name[k] != '.') count++; //if !='.' then just increment the count
      else{
          *prev = count; //store the count before again initializing it to 0
          count = 0;
          prev = (unsigned char *)name + k + 1; //change the location of prev to the next place where the current filed's length will be stored
      }
    }
  *prev = count; //prev is still pointing to last '.' so update it's location 
  question.name = name; //question.name now has the updated domain name without the dotted representation

  *len = sizeof (dns_header) + strlen (domain_name) + sizeof (question.class_of_dns) + sizeof (question.type_of_dns) + 2 ; //calc the combined length of all the fileds
  unsigned char *ptr = calloc (*len, sizeof (unsigned char)); //packet now points to the beginning of the space of len initialized with all 0's
  unsigned char *temp = ptr;

  memcpy (temp, &dns_header, sizeof (dns_header)); //copying the header first
  temp = temp + sizeof (dns_header);
  strcpy (temp, question.name); //copying the name 
  temp = temp + strlen (domain_name) + 2;
  memcpy (temp, &question.type_of_dns, sizeof (question.type_of_dns)); //copying the dns type
  temp = temp + sizeof (question.type_of_dns);
  memcpy (temp, &question.class_of_dns, sizeof (question.class_of_dns)); //copying the dns class

  return ptr;
}

int main (int argc, char *argv[]){
  if (argc < 2){ //checking if the domain name is passed or not
      printf("No domain name passed....\n"); 
      return -1;
    }
  if (argc > 2){ //checking if too many arguments passed
      printf("Too many arguments passed \n");
      return -1;
    }  
  char *domain_name = argv[1]; //storing the domain name that was passed by the user
  int len = 0;
  unsigned char *packet = append_packet (domain_name, &len); //append_packet function will append all the required headers needed

  printf ("Lookup Initiated for  %s\n\n", domain_name); //no error till now means the headers have been successfully appended

  int sock_fd = socket (AF_INET, SOCK_DGRAM, 0); //initiate the socket
  struct sockaddr_in server_addr;
  server_addr.sin_family = AF_INET; 
  server_addr.sin_addr.s_addr = htonl (0xd043dede);
  server_addr.sin_port = htons (53); //converts from host to networks byte order

  if(sendto (sock_fd, packet, len, 0, (struct sockaddr *)&server_addr,(socklen_t)sizeof (server_addr))==-1){ //packet sent to the DNS server
    printf("Error while sending packet to the DNS server\n");
    return -1;
  }
  unsigned char received_data[1024]; //buffer that stores the response that came from the server
  int recv_len;
  socklen_t length = 0;
  if((recv_len = recvfrom(sock_fd, received_data, sizeof(received_data), 0, (struct sockaddr *)&server_addr, &length))==-1){ //response now contains all the data received
    printf("Error while receiving response from the DNS server\n");
    return -1;
  }
  printf ("%s(IITH DNS) sent %d bytes....\n\n", inet_ntoa(server_addr.sin_addr),recv_len); //shows how many bytes received from the server

  struct header_info *response_header = (struct header_info *)received_data;
  if ((ntohs (response_header->flags) & 0xF) == 0){ //to check if the rcode is 0 or not, if 0 then processed correctly
      unsigned char *start_of_question = received_data + sizeof (struct header_info);
      struct question_info *dns_ques = calloc (sizeof (struct question_info), response_header->num_of_ans); //initializes the start pointer to all zeros
      dns_ques[0].name = (char *)start_of_question;
      unsigned char *curr_len = (unsigned char *)dns_ques[0].name;
      unsigned char total = 0;
      while (*curr_len != 0){
          total = total + *curr_len + 1;
          *curr_len = '.';
          curr_len = total + (unsigned char *)dns_ques[0].name ;
      }
      struct record_info *recorded_data = (struct record_info *)(curr_len + 5); //to skip null byte, type and class
      printf ("Information on %s\n\nIPv4: %s\nTTL: %d\nTYPE: %d(A)\nCLASS: %d(IN)\n", dns_ques[0].name+1, inet_ntoa (recorded_data[0].addr),ntohl (recorded_data[0].time_to_live),ntohs (recorded_data[0].type),ntohs (recorded_data[0].class));
      }
  else{
      printf("Didn't receive response\n");
      return -1;
    }
  return 0;
}