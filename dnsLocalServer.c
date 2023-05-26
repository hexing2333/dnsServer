#include <stdio.h>
#include "message.h"

#define SERVER_IP "127.1.1.1"
#define ROOT_IP "127.2.2.1"
#define SERVER_PORT 53
#define BUFFER_SIZE 1024

int main(int argc, char *argv[])
{
    // socket
    int sockfd, rootfd, clientfd;
    struct sockaddr_in server_addr, client_addr, up_addr;
    int send_len;
    int i;
    // dns
    unsigned char buffer[BUFFER_SIZE];
    unsigned char bufferTCP[BUFFER_SIZE];
    DNS_Header *dnsHeader = (DNS_Header *)buffer;
    DNS_Query *dnsQuery = (DNS_Query *)malloc(sizeof(DNS_Query *));
    DNS_RR *dnsRr = (DNS_RR *)malloc(sizeof(DNS_RR *));
    unsigned short oldID;
    unsigned char hostname[50] = {0};                     //plus dot hostname
    unsigned short *len_tcp = (unsigned short *)bufferTCP; //TCP packet Length
    unsigned char buffer_file[500] = {0};                   //file buf
    unsigned char tag_bit[16] = {0};

    memset(buffer, 0, sizeof(buffer));
    memset(bufferTCP, 0, sizeof(bufferTCP));
    memset(&server_addr, 0, sizeof(server_addr));
    memset(&client_addr, 0, sizeof(client_addr));
    memset(hostname, 0, sizeof(hostname));

    /*socket*/
    if ((sockfd = socket(AF_INET, SOCK_STREAM, 0)) == -1){
        printf("socket() created failed.\n");
        exit(1);
    }
    server_addr.sin_family = AF_INET;
    server_addr.sin_addr.s_addr = inet_addr(SERVER_IP);
    server_addr.sin_port = htons(SERVER_PORT);
    if ((bind(sockfd, (struct sockaddr *)&server_addr, sizeof(server_addr)) == -1)){
        printf("bind() failed.\n");
        exit(1);
    }
    if (listen(sockfd, 10) == -1){
        printf("listen() failed.\n");
        exit(1);
    }
    printf("The LocalServer Listen on %s,PORT:%d\n", SERVER_IP, SERVER_PORT);

    while (1){
        memset(hostname, 0, sizeof(hostname));
        memset(buffer, 0, sizeof(buffer));
        memset(bufferTCP, 0, sizeof(bufferTCP));
        i = sizeof(client_addr);
        clientfd = accept(sockfd, (struct sockaddr *)&client_addr, &i);
        if(clientfd == -1){
            printf("listen() failed.\n");
            continue;
        }
        int recvLen;
        recvLen = recv(clientfd, bufferTCP, BUFFER_SIZE, 0);
        memcpy(buffer, bufferTCP + 2, recvLen - 2);
        printf("receive %s:%d %dbytes.\n", inet_ntoa(client_addr.sin_addr), client_addr.sin_port, recvLen);
        oldID = ntohs(dnsHeader->id); //old id
        int queryLen = ReadQuery(dnsQuery, buffer + sizeof(DNS_Header));
        int rrLen;
        namePlusDot(hostname, dnsQuery->name, strlen(dnsQuery->name));
        FILE *fd;
        if ((fd = fopen("./file/dnsLocalCache.txt", "r+")) == NULL){
            printf("can't open the Cache file.\n");
            exit(1);
        }
        int isIncache = isInCache(buffer_file, hostname, fd);
        // printf("1111.\n");
        dnsRr->name = (unsigned char *)calloc(50, sizeof(unsigned char));
        printf("%s.\n",hostname);
        nameDeDot(dnsRr->name, hostname, strlen(hostname));
        // printf("33333.\n");
        readCache(dnsRr, buffer_file);
        // printf("22222.\n");
        if (isIncache == 1 && (dnsQuery->qtype == htons(A) && dnsRr->type == htons(A) ||
                          dnsQuery->qtype == htons(A) && dnsRr->type == htons(CNAME) ||
                          dnsQuery->qtype == htons(CNAME) && dnsRr->type == htons(CNAME) ||
                          dnsQuery->qtype == htons(MX) && dnsRr->type == htons(MX)))
        //In cache
        {
            // printf("33333.\n");
            dnsHeader->flags = htons(0x8180);  //reply
            dnsHeader->questionCount = htons(1);  
            dnsHeader->answerCount = htons(1); 
            dnsHeader->authorityCount = 0;
            dnsHeader->additionalCount = htons(0);

            rrLen = AddRR(buffer + sizeof(DNS_Header) + queryLen, dnsRr);
            
            if ((dnsQuery->qtype == htons(A) && dnsRr->type == htons(CNAME)) ||
                (dnsQuery->qtype == htons(MX) && dnsRr->type == htons(MX))) //CNAME or MX
            {
                // printf("444444.\n");
                namePlusDot(hostname, dnsRr->rdata, strlen(dnsRr->rdata));
                nameDeDot(dnsRr->name, hostname, strlen(hostname));
                readCache(dnsRr, buffer_file);
                dnsHeader->additionalCount = htons(1);
                //  printf("555555.\n");
                rrLen += AddRR(buffer + sizeof(DNS_Header) + queryLen + rrLen, dnsRr);
            }
            int sendLen = sizeof(DNS_Header) + queryLen + rrLen;
            *len_tcp = htons(sendLen);
            memcpy(bufferTCP + 2, buffer, sendLen);
            send_len = send(clientfd, bufferTCP, sendLen + 2, 0);
        }
        else{ //not in cache
            if ((rootfd = socket(AF_INET, SOCK_DGRAM, 0)) == -1){
                printf("rootfd failed.\n");
                exit(1);
            }
            server_addr.sin_port = htons(0);
            if ((bind(rootfd, (struct sockaddr *)&server_addr, sizeof(server_addr)) == -1)){
                printf("bind() failed.\n");
                exit(1);
            }
            memset(&up_addr, 0, sizeof(up_addr));
            up_addr.sin_family = AF_INET;
            up_addr.sin_addr.s_addr = inet_addr(ROOT_IP);
            up_addr.sin_port = htons(SERVER_PORT);

            /*Iterative*/
            unsigned short iter = 1;
            unsigned short tag = ntohs(dnsHeader->flags);
            while (1){
                dnsHeader->id = htons(oldID + iter++);//ID Iterative
                dnsHeader->flags = htons(0x0000); //request
                dnsHeader->questionCount = htons(1);
                dnsHeader->answerCount = 0;
                dnsHeader->authorityCount = 0;
                dnsHeader->additionalCount = 0;
                send_len = sendto(rootfd, buffer, sizeof(DNS_Header) + queryLen,
                                  0, (struct sockaddr *)&up_addr, sizeof(up_addr));
                printf("send %s:%d %d bytes.\n", inet_ntoa(up_addr.sin_addr),up_addr.sin_port, send_len);
                i = sizeof(struct sockaddr_in);
                recvLen = recvfrom(rootfd, buffer, BUFFER_SIZE, 0, (struct sockaddr *)&up_addr, &i);
                if (dnsHeader->answerCount == htons(1))
                    rrLen = HandleRR(dnsRr, buffer + sizeof(DNS_Header) + queryLen); //read Answer
                if (dnsHeader->additionalCount == htons(1))
                    rrLen += HandleRR(dnsRr, buffer + sizeof(DNS_Header) + queryLen + rrLen); //read Additional
                memcpy(&up_addr.sin_addr.s_addr, dnsRr->rdata, 4);
                memset(tag_bit, 0, sizeof(tag_bit));
                tag = ntohs(dnsHeader->flags);
                for (i = 0; i < 16; i++){
                    tag_bit[i] = tag % 2;
                    tag = tag / 2;
                }
                if (tag_bit[0] == 1 && tag_bit[1] == 1 || tag_bit[10] == 1)
                    break;
            }
            close(rootfd);
            dnsHeader->id = htons(oldID);
            if (tag_bit[0] == 1 && tag_bit[1] == 1) //no result
                dnsHeader->flags = htons(0x8183);        //reply result
            else
                dnsHeader->flags = htons(0x8180);
            *len_tcp = htons(recvLen);
            memcpy(bufferTCP + 2, buffer, recvLen);
            send_len = send(clientfd, bufferTCP, recvLen + 2, 0);
        }
        close(clientfd);
    }
    int enable = 1;
    if (setsockopt(sockfd, SOL_SOCKET, SO_REUSEADDR, &enable, sizeof(int)) < 0)
        perror("setsockopt(SO_REUSEADDR) failed");
    close(sockfd);
    return 0;
}
