#include <stdio.h>
#include <stdlib.h>
#include <unistd.h>
#include <sys/types.h>
#include <sys/socket.h>
#include <sys/sysinfo.h>
#include <netinet/in.h>
#include <net/if.h>
#include <linux/if.h>
#include <linux/if_ether.h>
#include <linux/ip.h>
#include <linux/tcp.h>
#include <linux/udp.h>
#include <linux/icmp.h>
#include <linux/if_packet.h>
#include <arpa/inet.h>
#include <sys/ioctl.h>
#include <inttypes.h>
#include <time.h>
#include <pthread.h>
#include <string.h>
#include <errno.h>

#include "config.h"
#include "sequence.h"
#include "utils.h"

#include "csum.h"

uint16_t threadsremaining;
uint64_t count[MAXSEQUENCES];
uint16_t seqcount;

/**
 * The thread handler for sending/receiving.
 * 
 * @param data Data (struct threadinfo) for the sequence.
 * @return void
 */
void *threadhdl(void *data)
{
    // Cast data as thread info.
    struct threadinfo *ti = (struct threadinfo *)data;

    // Let's parse some config values before creating the socket so we know what we're doing.
    uint8_t protocol = IPPROTO_UDP;
    uint8_t smac[ETH_ALEN];
    uint8_t dmac[ETH_ALEN];
    uint8_t payload[MAXPCKTLEN];
    uint16_t exactpayloadlen = 0;
    uint16_t id = 0;
    uint8_t ttl = 0;

    // Let's first start off by checking if the source MAC address is set within the config.
    if (ti->seq.eth.smac != NULL)
    {
        sscanf(ti->seq.eth.smac, "%hhx:%hhx:%hhx:%hhx:%hhx:%hhx", &smac[0], &smac[1], &smac[2], &smac[3], &smac[4], &smac[5]);
    }

    // Now check the destination MAC address.
    if (ti->seq.eth.dmac != NULL)
    {
        sscanf(ti->seq.eth.dmac, "%hhx:%hhx:%hhx:%hhx:%hhx:%hhx", &dmac[0], &dmac[1], &dmac[2], &dmac[3], &dmac[4], &dmac[5]);
    }

    // Now match the protocol (we exclude UDP since that's default).
    if (ti->seq.ip.protocol != NULL && !strcmp(lowerstr(ti->seq.ip.protocol), "tcp"))
    {
        protocol = IPPROTO_TCP;
    }
    else if (ti->seq.ip.protocol != NULL && !strcmp(lowerstr(ti->seq.ip.protocol), "icmp"))
    {
        protocol = IPPROTO_ICMP;
    }

    // Now check for the payload.
    if (ti->seq.payload.exact != NULL)
    {
        // Split argument by space.
        char *split;

        // Create temporary string.
        char *str = malloc((strlen(ti->seq.payload.exact) + 1) * sizeof(char));
        strcpy(str, ti->seq.payload.exact);

        split = strtok(str, " ");

        while (split != NULL)
        {
            sscanf(split, "%2hhx", &payload[exactpayloadlen]);
            
            exactpayloadlen++;
            split = strtok(NULL, " ");
        }

        // Free temporary string.
        free(str);
    }

    // Create sockaddr_ll struct.
    struct sockaddr_ll sin;

    // Fill out sockaddr_ll struct.
    sin.sll_family = PF_PACKET;
    sin.sll_ifindex = if_nametoindex(ti->device);
    sin.sll_protocol = htons(ETH_P_IP);
    sin.sll_halen = ETH_ALEN;

    // Initialize socket FD.
    int sockfd;

    // Attempt to create socket and also check for TCP cooked socket.
    uint8_t socktype = SOCK_RAW;
    uint8_t sockproto = IPPROTO_RAW;

    if (protocol == IPPROTO_TCP && ti->seq.tcp.usetcpsocket)
    {
        socktype = SOCK_STREAM;
        sockproto = IPPROTO_TCP;

        int one = 1;

        // Since we're setting up a TCP socket, we need to tell it we want to specify our own Ethernet and IP headers.
        if (setsockopt(sockfd, SOL_SOCKET, IP_HDRINCL, &one, sizeof(one)) != 0)
        {
            fprintf(stderr, "ERROR - Could not set IP_HDRINCL socket option :: %s.\n", strerror(errno));

            pthread_exit(NULL);
        }
    }

    if ((sockfd = socket(AF_PACKET, socktype, sockproto)) < 0)
    {
        fprintf(stderr, "ERROR - Could not setup socket :: %s.\n", strerror(errno));

        pthread_exit(NULL);
    }

    // Check if source MAC address is set properly. If not, let's get the MAC address of the interface we're sending packets out of.
    if (smac[0] == 0 && smac[1] == 0 && smac[2] == 0 && smac[3] == 0 && smac[4] == 0 && smac[5] == 0)
    {
        // Receive the interface's MAC address (the source MAC).
        struct ifreq ifr;
        
        strcpy(ifr.ifr_name, ti->device);

        // Attempt to get MAC address.
        if (ioctl(sockfd, SIOCGIFHWADDR, &ifr) != 0)
        {
            fprintf(stderr, "ERROR - Could not retrieve MAC address of interface :: %s.\n", strerror(errno));

            pthread_exit(NULL);
        }

        // Copy source MAC to necessary variables.
        memcpy(smac, ifr.ifr_addr.sa_data, ETH_ALEN);
    }

    memcpy(sin.sll_addr, smac, ETH_ALEN);

    // Check if destination MAC is set and if not, get the default gateway's MAC address.
    if (dmac[0] == 0 && dmac[1] == 0 && dmac[2] == 0 && dmac[3] == 0 && dmac[4] == 0 && dmac[5] == 0)
    {
        // Retrieve the default gateway's MAC address and store it in dmac.
        getgwmac((uint8_t *) &dmac);
    }

    // Attempt to bind socket.
    if (bind(sockfd, (struct sockaddr *)&sin, sizeof(sin)) != 0)
    {
        fprintf(stderr, "ERROR - Cannot bind to socket :: %s.\n", strerror(errno));

        pthread_exit(NULL);
    }

    // If TCP cooked socket, try to connect.
    /*
    if (ti->seq.tcp.usetcpsocket)
    {
        if (connect(sockfd, (struct sockaddr *)&sin, sizeof(sin)) != 0)
        {
            fprintf(stderr, "ERROR - Cannot connect to TCP socket :: %s.\n", strerror(errno));

            pthread_exit(NULL);
        }
    }
    */

    // Other packet variables for use inside of loop.
    uint16_t srcport;
    uint16_t dstport;
    char sip[32];

    time_t end = time(NULL) + ti->seq.time;
    uint16_t totaldata = 0;
    uint64_t pcktcount = 0;

    // Loop.
    while (1)
    {
        // Create rand_r() seed.
        unsigned int seed;

        seed = time(NULL) ^ getpid() ^ pthread_self() ^ pcktcount;

        // Assign source and destination ports if TCP or UDP.
        if (protocol == IPPROTO_TCP)
        {
            srcport = (ti->seq.tcp.srcport == 0) ? randnum(0, 65535, seed) : ti->seq.tcp.srcport;
            dstport = (ti->seq.tcp.dstport == 0) ? randnum(0, 65535, seed) : ti->seq.tcp.dstport;
        }
        else if (protocol == IPPROTO_UDP)
        {
            srcport = (ti->seq.udp.srcport == 0) ? randnum(0, 65535, seed) : ti->seq.udp.srcport;
            dstport = (ti->seq.udp.dstport == 0) ? randnum(0, 65535, seed) : ti->seq.udp.dstport;
        }

        // Check if source IP is defined. If not, get a random IP from the ranges.
        if (ti->seq.ip.srcip == NULL)
        {
            // Check if there are ranges.
            if (ti->seq.ip.rangecount > 0)
            {
                uint16_t ran = randnum(0, (ti->seq.ip.rangecount - 1), seed);

                // Ensure this range is valid.
                if (ti->seq.ip.ranges[ran] != NULL)
                {
                    if (pcktcount < ti->seq.count)
                    {
                        pcktcount++;
                    }
    
                    char *randip = randomip(ti->seq.ip.ranges[ran], &pcktcount);

                    if (randip != NULL)
                    {
                        strcpy(sip, randip);
                    }
                    else
                    {
                        goto fail;
                    }
                }
                else
                {
                    fail:
                    fprintf(stderr, "ERROR - Source range count is above 0, but string is NULL. Please report this! Using localhost...\n");

                    strcpy(sip, "127.0.0.1");
                }
            }
            else
            {
                // This shouldn't happen, but since it did, just assign localhost and warn the user.
                fprintf(stdout, "WARNING - No source IP or source range(s) specified. Using localhost...\n");

                strcpy(sip, "127.0.0.1");
            }
        }

        fprintf(stdout, "Using source IP %s\n", (ti->seq.ip.srcip != NULL) ? ti->seq.ip.srcip : sip);

        // Initialize buffer for packet and layer-4 header's length.
        char buffer[MAXPCKTLEN];
        uint8_t l4len;

        // Initialize Ethernet header.
        struct ethhdr *eth = (struct ethhdr *)(buffer);

        // Fill out Ethernet header.
        eth->h_proto = htons(ETH_P_IP);
        memcpy(eth->h_source, smac, ETH_ALEN);
        memcpy(eth->h_source, dmac, ETH_ALEN);

        // Initialize IP header.
        struct iphdr *iph = (struct iphdr *)(buffer + sizeof(struct ethhdr));

        // Fill out IP header generic fields.
        iph->ihl = 5;
        iph->version = 4;
        iph->protocol = protocol;
        iph->frag_off = 0;
        iph->tos = ti->seq.ip.tos;

        // TTL field.
        if (ti->seq.ip.ttl < 1)
        {
            ttl = randnum(ti->seq.ip.minttl, ti->seq.ip.maxttl, seed);
        }
        else
        {
            ttl = ti->seq.ip.ttl;
        }

        iph->ttl = ttl;

        // ID field.
        if (ti->seq.ip.id < 1)
        {
            id = randnum(ti->seq.ip.minid, ti->seq.ip.maxid, seed);
        }
        else
        {
            id = ti->seq.ip.id;
        }

        iph->id = id;

        // Source IP.
        struct in_addr saddr;
        inet_aton((ti->seq.ip.srcip != NULL) ? ti->seq.ip.srcip : sip, &saddr);

        iph->saddr = saddr.s_addr;

        // Destination IP.
        struct in_addr daddr;
        inet_aton(ti->seq.ip.dstip, &daddr);

        iph->daddr = daddr.s_addr;

        // Retrieve layer-4 header length.
        switch (protocol)
        {
            case IPPROTO_UDP:
                l4len = sizeof(struct udphdr);

                break;
            
            case IPPROTO_TCP:
                l4len = sizeof(struct tcphdr);

                break;

            case IPPROTO_ICMP:
                l4len = sizeof(struct icmphdr);

                break;
        }

        // Perform payload first so we can calculate checksum for layer-4 header later.
        unsigned char *data = (unsigned char *)(buffer + sizeof(struct ethhdr) + (iph->ihl * 4) + l4len);
        uint16_t datalen;

        // Check for custom payload.
        if (exactpayloadlen > 0)
        {
            datalen = exactpayloadlen;

            for (uint16_t i = 0; i < exactpayloadlen; i++)
            {
                *data = payload[i];
                (*data)++;
            }
        }
        else
        {
            datalen = randnum(ti->seq.payload.minlen, ti->seq.payload.maxlen, seed);

            // Fill out payload with random characters.
            for (uint16_t i = 0; i < datalen; i++)
            {
                *data = rand_r(&seed);
                (*data)++;
            }
        }

        // Fill out layer-4 header.
        if (protocol == IPPROTO_UDP)
        {
            struct udphdr *udph = (struct udphdr *)(buffer + sizeof(struct ethhdr) + (iph->ihl * 4));

            udph->source = htons(srcport);
            udph->dest = htons(dstport);
            udph->len = htons(l4len + datalen);

            if (ti->seq.l4csum)
            {
                udph->check = csum_tcpudp_magic(iph->saddr, iph->daddr, sizeof(struct udphdr) + datalen, IPPROTO_UDP, csum_partial(udph, sizeof(struct udphdr) + datalen, 0));
            }
        }
        else if (protocol == IPPROTO_TCP)
        {
            struct tcphdr *tcph = (struct tcphdr *)(buffer + sizeof(struct ethhdr) + (iph->ihl * 4));

            tcph->doff = 5;
            tcph->source = htons(srcport);
            tcph->dest = htons(dstport);
            
            // Flags.
            tcph->syn = ti->seq.tcp.syn;
            tcph->ack = ti->seq.tcp.ack;
            tcph->psh = ti->seq.tcp.psh;
            tcph->fin = ti->seq.tcp.fin;
            tcph->rst = ti->seq.tcp.rst;
            tcph->urg = ti->seq.tcp.urg;

            if (ti->seq.l4csum)
            {
                tcph->check = csum_tcpudp_magic(iph->saddr, iph->daddr, (tcph->doff * 4) + datalen, IPPROTO_TCP, csum_partial(tcph, (tcph->doff * 4) + datalen, 0));
            }
        }
        else
        {
            struct icmphdr *icmph = (struct icmphdr *)(buffer + sizeof(struct ethhdr) + (iph->ihl * 4));

            icmph->code = ti->seq.icmp.code;
            icmph->type = ti->seq.icmp.type;

            if (ti->seq.l4csum)
            {
                icmph->checksum = icmp_csum((uint16_t *)icmph, sizeof(struct icmphdr) + datalen);
            }
        }

        // Calculate IP header length.
        iph->tot_len = htons((iph->ihl * 4) + l4len + datalen);

        // IP header checksum.
        if (ti->seq.ip.csum)
        {
            update_iph_checksum(iph);
        }

        uint16_t sent;

        // Attempt to send packet.
        if ((sent = sendto(sockfd, buffer, ntohs(iph->tot_len) + sizeof(struct ethhdr), 0, (struct sockaddr *)&sin, sizeof(sin))) < 0)
        {
            fprintf(stderr, "ERROR - Could not send packet with length %lu :: %s.\n", (ntohs(iph->tot_len) + sizeof(struct ethhdr)), strerror(errno));
        }

        // Check time.
        if (ti->seq.time > 0 && time(NULL) >= end)
        {
            break;
        }

        // Check data.
        if (ti->seq.maxdata > 0)
        {
            totaldata += ntohs(iph->tot_len) + sizeof(struct ethhdr);

            if (totaldata >= ti->seq.maxdata)
            {
                break;
            }
        }

        // Increase count and check.
        if (ti->seq.count > 0 && ++pcktcount >= ti->seq.count)
        {
            break;
        }
    }

    // Close socket.
    close(sockfd);

    // Decrease thread remaining count for block mode.
    if (threadsremaining > 0)
    {
        threadsremaining--;
    }

    pthread_exit(NULL);
}

/**
 * Starts a sequence in send mode. 
 * 
 * @param interface The networking interface to send packets out of.
 * @param seq A singular sequence structure containing relevant information for the packet.
 * @return void
 */
void seqsend(const char *interface, struct sequence seq)
{
    // Create new threadinfo structure to pass to threads.
    struct threadinfo ti = {0};

    // Assign correct values to thread info.
    strcpy((char *)&ti.device, interface);
    memcpy(&ti.seq, &seq, sizeof(struct sequence));

    // Create the threads needed.
    int threads = (seq.threads > 0) ? seq.threads : get_nprocs();

    if (seq.block)
    {
        threadsremaining = threads;
    }

    ti.seqcount = seqcount;

    for (int i = 0; i < threads; i++)
    {
        // Create a duplicate of thread info structure to send to each thread.
        struct threadinfo *tidup = malloc(sizeof(struct threadinfo));
        memcpy(tidup, &ti, sizeof(struct threadinfo));

        pthread_t pid;

        pthread_create(&pid, NULL, threadhdl, (void *)tidup);
    }

    // Wait.
    if (seq.block)
    {
        while (threadsremaining > 0)
        {
            sleep(1);
        }
    }

    seqcount++;
}

/**
 * Starts a sequence in receive mode. 
 * 
 * @param interface The networking interface to send packets out of.
 * @param seq A singular sequence structure containing relevant information for the packet.
 * @return void
 */
void seqrecv(const char interface, struct sequence seq)
{

}