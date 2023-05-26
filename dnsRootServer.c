#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/socket.h>
#include <netinet/in.h>
#include <arpa/inet.h>

#include "message.h"

#define SERVER_IP "127.2.2.1"
#define SERVER_PORT 53
#define BUFFER_SIZE 1024

int main(int argc, char *argv[])
{
    int sockfd;
    struct sockaddr_in server_addr, client_addr;
    int i;

    unsigned char buffer[BUFFER_SIZE];
    DNS_Header *dnsHeader = (DNS_Header *)buffer;
    DNS_Query *dnsQuery = (DNS_Query *)malloc(sizeof(DNS_Query *));
    DNS_RR *dnsRr = (DNS_RR *)malloc(sizeof(DNS_RR *));
    FILE *file_descriptor;

    unsigned char domain_name[100] = {0};   //domain name
    unsigned char ns_domain_name[50] = {0}; // ns domain name
    unsigned char buffer_file[100] = {0};
    memset(buffer, 0, sizeof(buffer));
    memset(&server_addr, 0, sizeof(server_addr));
    memset(domain_name, 0, sizeof(domain_name));
    memset(ns_domain_name, 0, sizeof(ns_domain_name));
    if ((sockfd = socket(AF_INET, SOCK_DGRAM, 0)) == -1){
        printf("socket create failed.\n");
        exit(1);
    }
    server_addr.sin_family = AF_INET;
    server_addr.sin_addr.s_addr = inet_addr(SERVER_IP);
    server_addr.sin_port = htons(SERVER_PORT);

    if ((bind(sockfd, (struct sockaddr *)&server_addr, sizeof(server_addr)) == -1)){
        printf("socket bind() failed.\n");
        exit(1);
    }
    printf("The rootServer Listening on %s,PORT:%d\n", SERVER_IP, SERVER_PORT);
    while (1)
    {
        memset(buffer, 0, sizeof(buffer));
        memset(&client_addr, 0, sizeof(client_addr));
        memset(domain_name, 0, sizeof(domain_name));
        memset(ns_domain_name, 0, sizeof(ns_domain_name));
        i = sizeof(client_addr);
        int recvLen;
        recvLen = recvfrom(sockfd, buffer, BUFFER_SIZE, 0, (struct sockaddr *)&client_addr, &i);
        printf("receivefrom: %s %d\n", inet_ntoa(client_addr.sin_addr), client_addr.sin_port);
        int queryLen = ReadQuery(dnsQuery, buffer + sizeof(DNS_Header));
        int rrLen;
        namePlusDot(domain_name, dnsQuery->name, strlen(dnsQuery->name));
        i = strlen(domain_name);
        while (domain_name[i - 1] != '.') {
            i--;
        }
        // for (i = strlen(domain_name); domain_name[i - 1] != '.'; i--)
        //     ;
        strcpy(ns_domain_name, domain_name + i);
        
        if ((file_descriptor = fopen("./file/dnsRoot.txt", "r+")) == NULL){
            printf("open file failed.\n");
            exit(1);
        }
        int isIncache = isInCache(buffer_file, ns_domain_name, file_descriptor);

        if (isIncache == 1){                                                // in database
            dnsHeader->flags = htons(0x8000);    //0800
            dnsHeader->questionCount = htons(1); // 
            dnsHeader->answerCount = htons(1);   //
            dnsHeader->authorityCount = 0;
            dnsHeader->additionalCount = htons(1);
            dnsRr->name = (unsigned char *)calloc(50, sizeof(unsigned char));
            nameDeDot(dnsRr->name, ns_domain_name, strlen(ns_domain_name));
            readCache(dnsRr, buffer_file);
            rrLen = AddRR(buffer + sizeof(DNS_Header) + queryLen, dnsRr);
            namePlusDot(ns_domain_name, dnsRr->rdata, strlen(dnsRr->rdata));
            isIncache = isInCache(buffer_file, ns_domain_name, file_descriptor);
            if (isIncache == 1){
                nameDeDot(dnsRr->name, ns_domain_name, strlen(ns_domain_name));
                readCache(dnsRr, buffer_file);
                rrLen += AddRR(buffer + sizeof(DNS_Header) + queryLen + rrLen, dnsRr);
            }
        }
        else{                                           // not in database
            dnsHeader->flags = htons(0x8003); // no answer
            rrLen = 0;
        }
        int sendLen = sendto(sockfd, buffer, sizeof(DNS_Header) + queryLen + rrLen, 0, (struct sockaddr *)&client_addr, sizeof(client_addr));
        if (sendLen == -1){
            printf("sendto() failed.\n");
        }
    }
    fclose(file_descriptor);
    close(sockfd);
    return 0;
}