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
#include "cmdline.h"
#include "sequence.h"
#include "utils.h"

#include "csum.h"

uint64_t count[MAXSEQUENCES];
uint64_t totaldata[MAXSEQUENCES];
uint16_t seqcount;

/**
 * The thread handler for sending/receiving.
 * 
 * @param data Data (struct threadinfo) for the sequence.
 * @return void
 */
void *threadhdl(void *temp)
{
    // Cast data as thread info.
    struct threadinfo *ti = (struct threadinfo *)temp;

    // Let's parse some config values before creating the socket so we know what we're doing.
    uint8_t protocol = IPPROTO_UDP;
    uint8_t smac[ETH_ALEN];
    uint8_t dmac[ETH_ALEN];
    uint8_t payload[MAXPCKTLEN];
    uint16_t exactpayloadlen = 0;
    uint16_t datalen;

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
        char *payloadstr = NULL;

        // Check if payload is file.
        if (ti->seq.payload.isfile)
        {
            FILE *fp = fopen(ti->seq.payload.exact, "rb");
            uint64_t len = 0;

            // Check if our file is invalid. If so, print error and set empty payload string.
            if (fp == NULL)
            {
                fprintf(stderr, "Unable to open payload file (%s) :: %s.\n", ti->seq.payload.exact, strerror(errno));

                payloadstr = malloc(sizeof(char) * 2);
                strcpy(payloadstr, "");

                goto skippayload;
            }

            // Read file and store it in payload string.
            fseek(fp, 0, SEEK_END);
            len = ftell(fp);
            fseek(fp, 0, SEEK_SET);

            payloadstr = malloc(len);

            if (payloadstr)
            {
                fread(payloadstr, 1, len, fp);
            }

            fclose(fp);
        }
        else
        {
            payloadstr = strdup(ti->seq.payload.exact);
        }
        
        skippayload:;

        // Check if we want to parse the actual string.
        if (ti->seq.payload.isstring)
        {
            exactpayloadlen = strlen(payloadstr);

            memcpy(payload, payloadstr, exactpayloadlen);
        }
        else
        {
            // Split argument by space.
            char *split;
            char *rest = payloadstr;

            while ((split = strtok_r(rest, " ", &rest)))
            {
                sscanf(split, "%2hhx", &payload[exactpayloadlen]);
                
                exactpayloadlen++;
            }
        }

        free(payloadstr);
    }

    // Create sockaddr_ll struct.
    struct sockaddr_ll sin;

    // Fill out sockaddr_ll struct.
    sin.sll_family = PF_PACKET;
    sin.sll_ifindex = if_nametoindex((ti->seq.interface != NULL) ? ti->seq.interface : ti->device);
    sin.sll_protocol = htons(ETH_P_IP);
    sin.sll_halen = ETH_ALEN;

    // Initialize socket FD.
    int sockfd;

    // Attempt to create socket and also check for TCP cooked socket.
    uint8_t sockdomain = AF_PACKET;
    uint8_t socktype = SOCK_RAW;
    uint8_t sockproto = IPPROTO_RAW;

    if (protocol == IPPROTO_TCP && ti->seq.tcp.usetcpsocket)
    {
        sockdomain = AF_INET;
        socktype = SOCK_STREAM;
        sockproto = 0;
    }

    if ((sockfd = socket(sockdomain, socktype, sockproto)) < 0)
    {
        fprintf(stderr, "ERROR - Could not setup socket :: %s.\n", strerror(errno));

        pthread_exit(NULL);
    }

    // Check if source MAC address is set properly. If not, let's get the MAC address of the interface we're sending packets out of.
    if (smac[0] == 0 && smac[1] == 0 && smac[2] == 0 && smac[3] == 0 && smac[4] == 0 && smac[5] == 0)
    {
        // Receive the interface's MAC address (the source MAC).
        struct ifreq ifr;
        
        strcpy(ifr.ifr_name, (ti->seq.interface != NULL) ? ti->seq.interface : ti->device);

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

    // If TCP cooked socket, try to connect.
    if (protocol == IPPROTO_TCP && ti->seq.tcp.usetcpsocket)
    {
        // We'll want to construct a sockaddr_in instead.
        struct sockaddr_in tcpsin;
        tcpsin.sin_family = AF_INET;

        // Set destination IP and port (they must be static in order for TCP socket to work).
        struct in_addr daddr;
        inet_aton(ti->seq.ip.dstip, &daddr);

        tcpsin.sin_addr.s_addr = daddr.s_addr;
        tcpsin.sin_port = htons(ti->seq.tcp.dstport);
        memset(&tcpsin.sin_zero, 0, sizeof(tcpsin.sin_zero));
        
        if (connect(sockfd, (struct sockaddr *)&tcpsin, sizeof(tcpsin)) != 0)
        {
            fprintf(stderr, "ERROR - Cannot connect to destination using cooked sockets :: %s.\n", strerror(errno));

            pthread_exit(NULL);
        }
    }
    else
    {
        // Attempt to bind socket.
        if (bind(sockfd, (struct sockaddr *)&sin, sizeof(sin)) != 0)
        {
            fprintf(stderr, "ERROR - Cannot bind to socket :: %s.\n", strerror(errno));

            pthread_exit(NULL);
        }
    }

    /* Our goal below is to set as many things before the while loop as possible since any additional instructions inside the while loop will impact performance. */

    // Some variables to help decide the randomness of our packets.
    uint8_t needcsum = 1;
    uint8_t needl4csum = 1;
    uint8_t needlenrecal = 1;

    // Create rand_r() seed.
    unsigned int seed;

    // Initialize buffer for the packet itself.
    char buffer[MAXPCKTLEN];

    // Common packet characteristics.
    uint8_t l4len;

    // Source IP string for a random-generated IP address.
    char sip[32];

    // Initialize Ethernet header.
    struct ethhdr *eth = (struct ethhdr *)(buffer);

    // Initialize IP header.
    struct iphdr *iph = (struct iphdr *)(buffer + sizeof(struct ethhdr));

    // Initialize UDP, TCP, and ICMP headers. Declare them as NULL until we know what protocol we're dealing with.
    struct udphdr *udph = NULL;
    struct tcphdr *tcph = NULL;
    struct icmphdr *icmph = NULL;

    // Fill out Ethernet header.
    eth->h_proto = htons(ETH_P_IP);
    memcpy(eth->h_source, smac, ETH_ALEN);
    memcpy(eth->h_dest, dmac, ETH_ALEN);

    // Fill out IP header generic fields.
    iph->ihl = 5;
    iph->version = 4;
    iph->protocol = protocol;
    iph->frag_off = 0;
    iph->tos = ti->seq.ip.tos;

    // Check for static TTL.
    if (ti->seq.ip.minttl == ti->seq.ip.maxttl)
    {
        iph->ttl = ti->seq.ip.maxttl;
    }

    // Check for static ID.
    if (ti->seq.ip.minid == ti->seq.ip.maxid)
    {
        iph->id = htons(ti->seq.ip.maxid);
    }

    // Check for static source IP.
    if (ti->seq.ip.srcip != NULL)
    {
        struct in_addr saddr;
        inet_aton(ti->seq.ip.srcip, &saddr);

        iph->saddr = saddr.s_addr; 
    }

    // Destination IP.
    struct in_addr daddr;
    inet_aton(ti->seq.ip.dstip, &daddr);

    iph->daddr = daddr.s_addr;

    // Handle layer-4 header (UDP, TCP, or ICMP).
    switch (protocol)
    {
        case IPPROTO_UDP:
            udph = (struct udphdr *)(buffer + sizeof(struct ethhdr) + (iph->ihl * 4));
            l4len = sizeof(struct udphdr);

            // Check for static source/destination ports.
            if (ti->seq.udp.srcport > 0)
            {
                udph->source = htons(ti->seq.udp.srcport);
            }

            if (ti->seq.udp.dstport > 0)
            {
                udph->dest = htons(ti->seq.udp.dstport);
            }

            // If we have static/same payload length, let's set the UDP header's length here.
            if (exactpayloadlen > 0 || ti->seq.payload.minlen == ti->seq.payload.maxlen)
            {
                datalen = (exactpayloadlen > 0) ? exactpayloadlen : ti->seq.payload.maxlen;

                udph->len = htons(l4len + datalen);

                // If we have static payload length/data or our source/destination IPs/ports are static, we can calculate the UDP header's outside of while loop.
                if ((ti->seq.udp.srcport > 0 && ti->seq.udp.dstport > 0 && ti->seq.ip.srcip != NULL) && exactpayloadlen > 0)
                {
                    needl4csum = 0;
                }

                needlenrecal = 0;
            }

            break;
        
        case IPPROTO_TCP:
            tcph = (struct tcphdr *)(buffer + sizeof(struct ethhdr) + (iph->ihl * 4));

            tcph->doff = 5;
            l4len = (tcph->doff * 4);

            // Check for static source/destination ports.
            if (ti->seq.tcp.srcport > 0)
            {
                tcph->source = htons(ti->seq.tcp.srcport);
            }

            if (ti->seq.tcp.dstport > 0)
            {
                tcph->dest = htons(ti->seq.tcp.dstport);
            }

            // Flags.
            tcph->syn = ti->seq.tcp.syn;
            tcph->ack = ti->seq.tcp.ack;
            tcph->psh = ti->seq.tcp.psh;
            tcph->fin = ti->seq.tcp.fin;
            tcph->rst = ti->seq.tcp.rst;
            tcph->urg = ti->seq.tcp.urg;

            // Check if we need to do length recalculation later on.
            if (exactpayloadlen > 0 || ti->seq.payload.minlen == ti->seq.payload.maxlen)
            {
                datalen = (exactpayloadlen > 0) ? exactpayloadlen : ti->seq.payload.maxlen;

                needlenrecal = 0;
            }

            // If we have static payload length/data or our source/destination IPs/ports are static, we can calculate the TCP header's checksum here.
            if (!needlenrecal && (ti->seq.tcp.srcport > 0 && ti->seq.tcp.dstport > 0 && ti->seq.ip.srcip != NULL) && exactpayloadlen > 0)
            {
                needl4csum = 0;
            }

            break;

        case IPPROTO_ICMP:
            icmph = (struct icmphdr *)(buffer + sizeof(struct ethhdr) + (iph->ihl * 4));
            l4len = sizeof(struct icmphdr);

            // Set code and type.
            icmph->code = ti->seq.icmp.code;
            icmph->type = ti->seq.icmp.type;

            // If we have static payload length/data, we can calculate the ICMP header's checksum outside of while loop.
            if (exactpayloadlen > 0 || ti->seq.payload.minlen == ti->seq.payload.maxlen)
            {
                datalen = (exactpayloadlen > 0) ? exactpayloadlen : ti->seq.payload.maxlen;

                needlenrecal = 0;

                if (exactpayloadlen > 0)
                {
                    needl4csum = 0;
                }
            }

            break;
    }

    // Check if we can set static IP header length.
    if (!needlenrecal)
    {
        iph->tot_len = htons((iph->ihl * 4) + l4len + datalen);
    }

    // Check if we need to calculate the IP checksum later on or not. If not, calculate now.
    if (ti->seq.ip.minttl == ti->seq.ip.maxttl && ti->seq.ip.minid == ti->seq.ip.maxid && ti->seq.ip.srcip != NULL && !needlenrecal)
    {
        needcsum = 0;

        if (ti->seq.ip.csum)
        {
            update_iph_checksum(iph);
        }
    }

    // Initialize payload data.
    unsigned char *data = (unsigned char *)(buffer + sizeof(struct ethhdr) + (iph->ihl * 4) + l4len);

    // Check for exact payload.
    if (exactpayloadlen > 0)
    {
        for (uint16_t i = 0; i < exactpayloadlen; i++)
        {
            *(data + i) = payload[i];
        }

        // Calculate UDP and ICMP header's checksums.
        if (!needl4csum && protocol == IPPROTO_UDP && ti->seq.l4csum)
        {
            udph->check = 0;
            udph->check = csum_tcpudp_magic(iph->saddr, iph->daddr, l4len + datalen, IPPROTO_UDP, csum_partial(udph, l4len + datalen, 0));
        }
        else if (!needl4csum && protocol == IPPROTO_TCP && ti->seq.l4csum)
        {
            tcph->check = 0;
            tcph->check = csum_tcpudp_magic(iph->saddr, iph->daddr, (tcph->doff * 4) + datalen, IPPROTO_TCP, csum_partial(tcph, (tcph->doff * 4) + datalen, 0));
        }
        else if (!needl4csum && protocol == IPPROTO_ICMP && ti->seq.l4csum)
        {
            icmph->checksum = 0;
            icmph->checksum = icmp_csum((uint16_t *)icmph, l4len + datalen);
        }
    }

    // Check for static payload.
    if (exactpayloadlen < 1 && ti->seq.payload.staticdata)
    {
        datalen = randnum(ti->seq.payload.minlen, ti->seq.payload.maxlen, seed);

        // Fill out payload with random characters.
        for (uint16_t i = 0; i < datalen; i++)
        {
            *(data + i) = rand_r(&seed);
        }

        // Recalculate UDP/ICMP checksums and ensure we don't calculate them again in while loop since we don't need to (will improve performance).
        if (!needlenrecal)
        {
            if (protocol == IPPROTO_UDP && ti->seq.l4csum)
            {
                udph->check = 0;
                udph->check = csum_tcpudp_magic(iph->saddr, iph->daddr, l4len + datalen, IPPROTO_UDP, csum_partial(udph, l4len + datalen, 0));
            }
            if (protocol == IPPROTO_TCP && ti->seq.l4csum)
            {
                tcph->check = 0;
                tcph->check = csum_tcpudp_magic(iph->saddr, iph->daddr, (tcph->doff * 4) + datalen, IPPROTO_TCP, csum_partial(tcph, (tcph->doff * 4) + datalen, 0));
            }
            else if (protocol == IPPROTO_ICMP && ti->seq.l4csum)
            {
                icmph->checksum = 0;
                icmph->checksum = icmp_csum((uint16_t *)icmph, l4len + datalen);
            }

            needl4csum = 0;
        }
    }

    // Set ending time.
    time_t end = time(NULL) + ti->seq.time;

    // Loop.
    while (1)
    {
        // Increase count and check.
        if (ti->seq.count > 0 || ti->seq.trackcount)
        {
            if (ti->seq.count > 0 && count[ti->seqcount] >= ti->seq.count)
            {
                break;
            }

            __sync_add_and_fetch(&count[ti->seqcount], 1);
        }

        // Check time.
        if (ti->seq.time > 0 && time(NULL) >= end)
        {
            break;
        }

        seed = time(NULL) ^ count[ti->seqcount];

        /* Assign random IP header values if need to be. */

        // Check for random TTL.
        if (ti->seq.ip.minttl != ti->seq.ip.maxttl)
        {
            iph->ttl = randnum(ti->seq.ip.minttl, ti->seq.ip.maxttl, seed);
        }

        // Check for random ID.
        if (ti->seq.ip.minid != ti->seq.ip.maxid)
        {
            iph->id = htons(randnum(ti->seq.ip.minid, ti->seq.ip.maxid, seed));
        }

        // Check if source IP is defined. If not, get a random IP from the ranges and assign it to the IP header's source IP.
        if (ti->seq.ip.srcip == NULL && !ti->seq.tcp.usetcpsocket)
        {
            // Check if there are ranges.
            if (ti->seq.ip.rangecount > 0)
            {
                uint16_t ran = randnum(0, (ti->seq.ip.rangecount - 1), seed);

                // Ensure this range is valid.
                if (ti->seq.ip.ranges[ran] != NULL)
                {
                    if (ti->seq.count < 1 && !ti->seq.trackcount)
                    {
                        count[ti->seqcount]++;
                    }
    
                    char *randip = randomip(ti->seq.ip.ranges[ran], &count[ti->seqcount]);

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

            // Copy 32-bit IP address to IP header in network byte order.
            struct in_addr saddr;
            inet_aton(sip, &saddr);

            iph->saddr = saddr.s_addr;
        }
        
        // Check if we need to calculate random payload.
        if (exactpayloadlen < 1 && !ti->seq.payload.staticdata)
        {
            datalen = randnum(ti->seq.payload.minlen, ti->seq.payload.maxlen, seed);

            // Fill out payload with random characters.
            for (uint16_t i = 0; i < datalen; i++)
            {
                *(data + i) = rand_r(&seed);
            }
        }

        // Check layer-4 protocols and assign random characteristics if need to be.
        if (protocol == IPPROTO_UDP)
        {
            // Check for random source port.
            if (ti->seq.udp.srcport == 0)
            {
                udph->source = htons(randnum(1, 65535, seed));
            }

            // Check for random destination port.
            if (ti->seq.udp.dstport == 0)
            {
                udph->dest = htons(randnum(1, 65535, seed));
            }

            // Check for UDP length recalculation.
            if (needlenrecal)
            {
                udph->len = htons(l4len + datalen);
            }

            // Check for UDP checksum recalculation.
            if (needl4csum && ti->seq.l4csum)
            {
                udph->check = 0;
                udph->check = csum_tcpudp_magic(iph->saddr, iph->daddr, sizeof(struct udphdr) + datalen, IPPROTO_UDP, csum_partial(udph, sizeof(struct udphdr) + datalen, 0));   
            }
        }
        else if (protocol == IPPROTO_TCP)
        {
            if (ti->seq.tcp.srcport == 0)
            {
                tcph->source = htons(randnum(1, 65535, seed));
            }

            if (ti->seq.tcp.dstport == 0)
            {
                tcph->dest = htons(randnum(1, 65535, seed));
            }

            // Check if we need to calculate checksum.
            if (needl4csum && ti->seq.l4csum)
            {
                tcph->check = 0;
                tcph->check = csum_tcpudp_magic(iph->saddr, iph->daddr, (tcph->doff * 4) + datalen, IPPROTO_TCP, csum_partial(tcph, (tcph->doff * 4) + datalen, 0));   
            }
        }
        else if (protocol == IPPROTO_ICMP)
        {
            if (needl4csum && ti->seq.l4csum)
            {
                icmph->checksum = 0;
                icmph->checksum = icmp_csum((uint16_t *)icmph, l4len + datalen);
            }
        }
        
        // Check for length recalculation for IP header.
        if (needlenrecal)
        {
            iph->tot_len = htons((iph->ihl * 4) + l4len + datalen);
        }

        // Check if we need to calculate IP checksum.
        if (needcsum && ti->seq.ip.csum)
        {
            update_iph_checksum(iph);
        }

        uint16_t sent;

        // Attempt to send packet.
        if (protocol == IPPROTO_TCP && ti->seq.tcp.usetcpsocket)
        {
            if ((sent = send(sockfd, data, datalen, 0)) < 0)
            {
                fprintf(stderr, "ERROR - Could not send TCP (cooked) packet with length %hu :: %s.\n", (ntohs(iph->tot_len)), strerror(errno));
            }
        }
        else
        {
            if ((sent = send(sockfd, buffer, ntohs(iph->tot_len) + sizeof(struct ethhdr), 0)) < 0)
            {
                fprintf(stderr, "ERROR - Could not send packet with length %lu :: %s.\n", (ntohs(iph->tot_len) + sizeof(struct ethhdr)), strerror(errno));
            }
        }

        // Check if we want to send verbose output or not.
        if (ti->cmd.verbose && sent > 0)
        {
            // Retrieve source and destination ports for UDP/TCP protocols.
            uint16_t srcport = 0;
            uint16_t dstport = 0;

            if (protocol == IPPROTO_UDP)
            {
                srcport = ntohs(udph->source);
                dstport = ntohs(udph->dest);
            }
            else if (protocol == IPPROTO_TCP)
            {
                srcport = ntohs(tcph->source);
                dstport = ntohs(tcph->dest);
            }

            fprintf(stdout, "Sent %d bytes of data from %s:%d to %s:%d.\n", sent, (ti->seq.ip.srcip != NULL) ? ti->seq.ip.srcip : sip, srcport, ti->seq.ip.dstip, dstport);
        }

        // Check data.
        if (ti->seq.maxdata > 0)
        {
            if (totaldata[ti->seqcount] >= ti->seq.maxdata)
            {
                break;
            }

            __sync_add_and_fetch(&totaldata[ti->seqcount], ntohs(iph->tot_len) + sizeof(struct ethhdr));
        }

        // Check for delay.
        if (ti->seq.delay > 0)
        {
            usleep(ti->seq.delay);
        }
    }

    // Close socket.
    close(sockfd);

    pthread_exit(NULL);
}

/**
 * Starts a sequence in send mode. 
 * 
 * @param interface The networking interface to send packets out of.
 * @param seq A singular sequence structure containing relevant information for the packet.
 * @return void
 */
void seqsend(const char *interface, struct sequence seq, uint16_t seqc, struct cmdline cmd)
{
    // First, let's check if the destination IP is set.
    if (seq.ip.dstip == NULL)
    {
        fprintf(stdout, "Destination IP not set on sequence #%" PRIu16 ". Not moving forward with this sequence.\n", seqcount);

        return;
    }

    // Create new threadinfo structure to pass to threads.
    struct threadinfo ti = {0};

    // Assign correct values to thread info.
    strcpy((char *)&ti.device, interface);
    memcpy(&ti.seq, &seq, sizeof(struct sequence));

    // Copy command line.
    ti.cmd = cmd;

    // Create the threads needed.
    int threads = (seq.threads > 0) ? seq.threads : get_nprocs();

    // Reset count and total data for this sequence.
    count[seqcount] = 0;
    totaldata[seqcount] = 0;

    ti.seqcount = seqcount;

    pthread_t pid[MAXTHREADS];

    for (int i = 0; i < threads; i++)
    {
        // Create a duplicate of thread info structure to send to each thread.
        struct threadinfo *tidup = malloc(sizeof(struct threadinfo));
        memcpy(tidup, &ti, sizeof(struct threadinfo));

        pthread_create(&pid[i], NULL, threadhdl, (void *)tidup);
    }

    // Check for block or if this is the last sequence (we'd want to join threads so the main thread exits after completion).
    if (seq.block || (seqcount) >= (seqc - 1))
    {
        for (int i = 0; i < threads; i++)
        {
            pthread_join(pid[i], NULL);
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