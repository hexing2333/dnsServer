#include<stdio.h>
#include "message.h"

#define SERVER_PORT 53
#define SERVER_IP "127.1.1.1"

int PrintRR(struct DNS_RR *dnsRr);
int main(int argc,char *argv[]){
    /*socket*/
    
    int sockfd = 0;
    struct sockaddr_in serv_addr;
    int sendLen,recvLen;
    

    /*DNS Message*/
    unsigned char buffer[BUFFER_SIZE];
    unsigned char buffer1[BUFFER_SIZE];
    struct DNS_Header *dnsHeader = (struct DNS_Header *)buffer;
    struct DNS_RR *dnsRr = (struct DNS_RR *)malloc(sizeof(DNS_RR *));
    struct DNS_Query *dnsQuery = (struct DNS_Query *)malloc(sizeof(DNS_Query *));
    unsigned char hostname[100];
    unsigned char qtype[100];
 
    
    strcpy(hostname, argv[1]);
    strcpy(qtype, argv[2]);

    memset(buffer1, 0, BUFFER_SIZE);
    memset(buffer, 0, BUFFER_SIZE);
    memset(&serv_addr, 0, sizeof(serv_addr));
   
   /*DNS header*/
    if (dnsHeader == NULL){
        printf("error to create dnsHeader");
    }else{
	    dnsHeader->id = htons(0x0001);//random ID
	    dnsHeader->flags = htons(0x0100);
	    //only one
	    dnsHeader->questionCount = htons(1); 
        dnsHeader->answerCount = 0;
        dnsHeader->authorityCount = 0;
        dnsHeader->additionalCount = 0;
    }
    /*DNS Query*/
    if (dnsQuery == NULL || hostname == NULL){
        printf("error to create dnsQuery");
    }else{
	    //plus 2
	    dnsQuery->name = (unsigned char *)calloc(50, sizeof(unsigned char));
	    if (dnsQuery->name == NULL) {
		    printf("error to create dnsQueryName");
	    }else{
            //set type
            if (strcmp(qtype, "A") == 0)
                dnsQuery->qtype = htons(A);
            else if (strcmp(qtype, "CNAME") == 0)
                dnsQuery->qtype = htons(CNAME);
            else if (strcmp(qtype, "MX") == 0)
                dnsQuery->qtype = htons(MX);
	        //set class
	        dnsQuery->qclass = htons(0x0001);
	        // set name 
	        unsigned char *p1, *p2;
            int i = 0;
            memset(dnsQuery->name, 0, sizeof(dnsQuery->name));
            p1 = hostname;
            p2 = dnsQuery->name + 1;
            while (p1 < (hostname + strlen(hostname))){
                if (*p1 == '.'){
                    *(p2 - i - 1) = i;
                    i = 0;
                }else{
                    *p2 = *p1;
                    i++;
                }
                p2++;
                p1++;
            }
            *(p2 - i - 1) = i;
        } 
    }
    /*construct tcp message*/
    int len;
    unsigned char *p = buffer + sizeof(DNS_Header);
    len = strlen(dnsQuery->name) + 1;
    memcpy(p, dnsQuery->name, len);
    p += len;
    memcpy(p, &dnsQuery->qtype, 2);
    p += 2;
    memcpy(p, &dnsQuery->qclass, 2);
    int QueryLen =  len + 4;
    // unsigned short *tcpLen = (unsigned short *)buffer1;
    // *tcpLen = htons(sizeof(DNS_Header)+QueryLen);
    memcpy(buffer1 + 2, buffer, sizeof(DNS_Header) + QueryLen);


    /*socket*/
   
    // if ((sockfd = socket(AF_INET, SOCK_DGRAM, 0)) == -1){ //STREAM TCP
    //     printf("socket() created failed.\n");
    //     exit(1);
    // } 
    if ((sockfd = socket(AF_INET, SOCK_STREAM, 0)) == -1){ //STREAM TCP
        printf("socket() created failed.\n");
        exit(1);
    }
    serv_addr.sin_family = AF_INET;
    serv_addr.sin_addr.s_addr = inet_addr(SERVER_IP);
    serv_addr.sin_port = htons(SERVER_PORT);
    if (connect(sockfd, (struct sockaddr *)&serv_addr, sizeof(serv_addr)) == -1)
    {
        printf("connect() failed.\n");
        exit(1);
    }
    int sendSize = sizeof(DNS_Header) + QueryLen + 2;
    sendLen = send(sockfd, buffer1, sendSize, 0);
    printf("send: %d bytes.\nSeek for domain: %s\n", sendLen, argv[1]);
    recvLen = recv(sockfd, buffer1, BUFFER_SIZE, 0);
    memcpy(buffer, buffer1 + 2, recvLen - 2);
    printf("receive: %d bytes.\n", recvLen);

    unsigned short flags = ntohs(dnsHeader->flags);
    unsigned char flagsChar[16] = {0};
    int RRLen;
    for (int i = 0; i < 16; i++){
        flagsChar[i] = flags % 2;
        flags = flags / 2;
    }
    if (flagsChar[0] == 1 && flagsChar[1] == 1)
        printf("Find Nothing!Please retry!\n");
    else{
        RRLen = HandleRR(dnsRr, buffer + sizeof(DNS_Header) + QueryLen);
        PrintRR(dnsRr);
        if (dnsHeader->additionalCount == htons(1)){
            RRLen = HandleRR(dnsRr, buffer + sizeof(DNS_Header) + QueryLen + RRLen);
            PrintRR(dnsRr);
        }
    }
    close(sockfd);
    return 0;
}

int PrintRR(struct DNS_RR *dnsRr)
{
    unsigned char buf[50] = {0};
    namePlusDot(buf, dnsRr->name, strlen(dnsRr->name));
    printf("%s ", buf);
    if (dnsRr->type == htons(A)){
        printf("A ");
        printf("%u.%u.%u.%u ", dnsRr->rdata[0],
               dnsRr->rdata[1], dnsRr->rdata[2], dnsRr->rdata[3]);
    }
    else if (dnsRr->type == htons(CNAME)){
        printf("CNAME ");
        namePlusDot(buf, dnsRr->rdata, strlen(dnsRr->rdata));
        printf("%s ", buf);
    }
    else if (dnsRr->type == htons(MX)){
        printf("MX %d ", ntohs(dnsRr->perference));
        namePlusDot(buf, dnsRr->rdata, strlen(dnsRr->rdata));
        printf("%s ", buf);
    }
    if (dnsRr->_class == htons(0x0001))
        printf("IN ");
    printf("%d\n", ntohl(dnsRr->ttl));
    return 0;
}