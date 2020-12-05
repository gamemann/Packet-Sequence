#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <errno.h>

#include <yaml.h>

#include "config.h"
#include "utils.h"

/**
 * Parses a config file including the main config options and sequences. It then fills out the config structure passed in the function's parameters.
 * 
 * @param filename The YAML config file to parse.
 * @param cfg A pointer to a config structure that'll be filled in with values.
 * @param onlyseq If set to 1, this function will only parse sequences and add onto the number.
 * @param seqnum A pointer to the current sequence # (starting from 0).
 * @return Returns 0 on success and 1 on failure.
 */
int parseconfig(const char filename[], struct config *cfg, int onlyseq, int *seqnum)
{
    // Attempt to open config file.
    FILE *fp = fopen(filename, "r");

    // Check if file pointer is valid.
    if (fp == NULL)
    {
        fprintf(stderr, "Error opening YAML config file (%s) :: %s.\n", filename, strerror(errno));

        return 1;
    }

    // Create YAML variables.
    yaml_parser_t parser;
    yaml_event_t ev;

    // Initialize parser.
    if (!yaml_parser_initialize(&parser))
    {
        fprintf(stderr, "Error initializing YAML parser (#%d) :: %s.\n", parser.error, strerror(errno));

        return 1;
    }

    // Set parser's input file.
    yaml_parser_set_input_file(&parser, fp);

    // General YAML.
    char *prevkey = NULL;
    //char *prevsec;

    // Sequences.
    int insequence = 0;
    int insequences = 0;
    char *curseq;

    // Sequence-specific.
    int inincludes = 0;
    int ineth = 0;
    int inip = 0;
    int inudp = 0;
    int intcp = 0;
    int inicmp = 0;
    int inpayload = 0;

    // Additional IP.
    int inttl = 0;
    int inranges = 0;
    int inid = 0;
    
    // Additional payload.
    int inlength = 0;
    
    do
    {
        // Keep scanning.
        if (!yaml_parser_parse(&parser, &ev))
        {
            fprintf(stderr, "Error parsing YAML file (#%d) :: %s.\n", parser.error, strerror(errno));

            return 1;
        }

        switch (ev.type)
        {
            case YAML_MAPPING_START_EVENT:
                // This occurs when we start a new mapping section. We want to check the previous key to see if it matches a mapping section we're expecting.
                
                // Check if we're already inside a sequence.
                if (insequence)
                {
                    // Check if we're in an existing mapping within the sequence.
                    if (inip)
                    {
                        // Now check if we're entering the TTL mapping.
                        if (prevkey != NULL && !strcmp(prevkey, "ttl"))
                        {
                            inttl = 1;
                        }
                        // Check if we're entering the ID mapping.
                        else if (prevkey != NULL && !strcmp(prevkey, "id"))
                        {
                            inid = 1;
                        }
                    }

                    if (inpayload)
                    {
                        if (prevkey != NULL && !strcmp(prevkey, "length"))
                        {
                            inlength = 1;
                        }
                    }

                    // Check for additional mappings inside a single sequence.
                    if (!ineth && prevkey != NULL && !strcmp(prevkey, "eth"))
                    {
                        ineth = 1;
                    }

                    if (!inip && prevkey != NULL && !strcmp(prevkey, "ip"))
                    {
                        inip = 1;
                    }

                    if (!inudp && prevkey != NULL && !strcmp(prevkey, "udp"))
                    {
                        inudp = 1;
                    }

                    if (!intcp && prevkey != NULL && !strcmp(prevkey, "tcp"))
                    {
                        intcp = 1;
                    }

                    if (!inicmp && prevkey != NULL && !strcmp(prevkey, "icmp"))
                    {
                        inicmp = 1;
                    }

                    if (!inpayload && prevkey != NULL && !strcmp(prevkey, "payload"))
                    {
                        inpayload = 1;
                    }
                }
                

                // Check for start of sequences.
                if (insequences == 0 && prevkey != NULL && !strcmp(prevkey, "sequences"))
                {
                    // We're now inside of the sequences map.
                    insequences = 1;
                }
                
                // Check if we're inside sequences already, but not inside of a single sequence.
                if (insequences && !insequence)
                {
                    // We're now entering a separate sequence.
                    insequence = 1;

                    curseq = strdup(prevkey);
                }

                break;
            
            case YAML_MAPPING_END_EVENT:
                // Check if we're in inside of sequences.
                if (insequences)
                {
                    // Check if we're inside a single sequence.
                    if (insequence)
                    {
                        // Now go through each mapping inside of a single sequence and do additional checks.
                        if (inincludes)
                        {
                            inincludes = 0;
                        }
                        else if (ineth)
                        {
                            ineth = 0;
                        }
                        else if (inip)
                        {
                            // Check for TTL mapping.
                            if (inttl)
                            {
                                inttl = 0;
                            }
                            else if (inid)
                            {
                                inid = 0;
                            }
                            else
                            {
                                inip = 0;
                            }
                        }
                        else if (inudp)
                        {
                            inudp = 0;
                        }
                        else if (intcp)
                        {
                            intcp = 0;
                        }
                        else if (inicmp)
                        {
                            inicmp = 0;
                        }
                        else if (inpayload)
                        {
                            // Check if we're in length mapping.
                            if (inlength)
                            {
                                inlength = 0;
                            }
                            else
                            {
                                inpayload = 0;
                            }
                        }
                        else
                        {
                            // Since everything else wasn't set, we should be exiting the sequence.
                            insequence = 0;

                            // Increase sequence count since the last one should have ended.
                            (*seqnum)++;
                        }
                    }
                    else
                    {
                        // We should be exiting sequences all together in this case.
                        insequences = 0;
                    }
                }
                
                break;

            case YAML_SEQUENCE_START_EVENT:
                // Check for includes or ranges.
                if (insequence)
                {
                    if (!inincludes && prevkey != NULL && !strcmp(prevkey, "includes"))
                    {
                        inincludes = 1;
                    }

                    if (!inranges && inip && prevkey != NULL && !strcmp(prevkey, "ranges"))
                    {
                        inranges = 1;
                    }
                }

                break;

            case YAML_SEQUENCE_END_EVENT:
                // Check if we're exiting includes or ranges.
                if (insequence && inincludes)
                {
                    inincludes = 0;
                }

                if (insequence && inip && inranges)
                {
                    inranges = 0;
                }
            
                break;

            case YAML_SCALAR_EVENT:
                // We want to check keys and values within the scalar (typically `key: value`).

                if (parser.state == YAML_PARSE_BLOCK_MAPPING_VALUE_STATE)
                {
                    // Assign prevkey to the value since this is representing a key.
                    prevkey = strdup((const char *)ev.data.scalar.value);
                }
                else if (parser.state == YAML_PARSE_BLOCK_MAPPING_KEY_STATE || parser.state == YAML_PARSE_BLOCK_SEQUENCE_ENTRY_STATE)
                {
                    // Check if we're within a sequence or not.
                    if (insequence)
                    {
                        // Check if we're within mappings inside the sequence.
                        if (inincludes)
                        {
                            fprintf(stdout, "Found an include!\n");

                            // Since we don't care about the key, just add onto the structure and increment the count.
                            cfg->seq[*seqnum].includes[cfg->seq[*seqnum].includecount] = strdup((const char *)ev.data.scalar.value);

                            // Increment count.
                            cfg->seq[*seqnum].includecount++;
                        }
                        else if (ineth)
                        {
                            // Check for source MAC.
                            if (prevkey != NULL && !strcmp(prevkey, "smac"))
                            {
                                cfg->seq[*seqnum].eth.smac = strdup((const char *)ev.data.scalar.value);
                            }

                            // Check for destination MAC.
                            if (prevkey != NULL && !strcmp(prevkey, "dmac"))
                            {
                                cfg->seq[*seqnum].eth.dmac = strdup((const char *)ev.data.scalar.value);
                            }
                        }
                        else if (inip)
                        {
                            // Check if we're within the TTL mapping.
                            if (inttl)
                            {
                                // Check for min TTL.
                                if (prevkey != NULL && !strcmp(prevkey, "minttl"))
                                {
                                    cfg->seq[*seqnum].ip.minttl = (uint8_t) atoi((const char *)ev.data.scalar.value);
                                }

                                // Check for max TTL.
                                if (prevkey != NULL && !strcmp(prevkey, "maxttl"))
                                {
                                    cfg->seq[*seqnum].ip.maxttl = (uint8_t) atoi((const char *)ev.data.scalar.value);
                                }
                            }
                            else if (inid)
                            {
                                // Check for min TTL.
                                if (prevkey != NULL && !strcmp(prevkey, "minid"))
                                {
                                    cfg->seq[*seqnum].ip.minid = (uint8_t) atoi((const char *)ev.data.scalar.value);
                                }

                                // Check for max TTL.
                                if (prevkey != NULL && !strcmp(prevkey, "maxid"))
                                {
                                    cfg->seq[*seqnum].ip.maxid = (uint8_t) atoi((const char *)ev.data.scalar.value);
                                }  
                            }
                            else if (inranges)
                            {
                                // Since we don't care about the key in ranges, simply add it and increase range count.
                                cfg->seq[*seqnum].ip.ranges[cfg->seq[*seqnum].ip.rangecount] = strdup((const char *)ev.data.scalar.value);

                                cfg->seq[*seqnum].ip.rangecount++;
                            }
                            else
                            {
                                // Look for all other IP options.

                                // Check for source IP.
                                if (prevkey != NULL && !strcmp(prevkey, "srcip"))
                                {
                                    cfg->seq[*seqnum].ip.srcip = strdup((const char *)ev.data.scalar.value);
                                }

                                // Check for destination IP.
                                if (prevkey != NULL && !strcmp(prevkey, "dstip"))
                                {
                                    cfg->seq[*seqnum].ip.dstip = strdup((const char *)ev.data.scalar.value);
                                }

                                // Check for protocol.
                                if (prevkey != NULL && !strcmp(prevkey, "protocol"))
                                {
                                    cfg->seq[*seqnum].ip.protocol = strdup((const char *)ev.data.scalar.value);
                                }

                                // Check for TOS.
                                if (prevkey != NULL && !strcmp(prevkey, "tos"))
                                {
                                    cfg->seq[*seqnum].ip.tos = (uint8_t) atoi((const char *)ev.data.scalar.value);
                                }

                                // Check for IP checksum calculation.
                                if (prevkey != NULL && !strcmp(prevkey, "csum"))
                                {
                                    cfg->seq[*seqnum].ip.csum = (!strcmp(lowerstr((char *)ev.data.scalar.value), "true")) ? 1 : 0;
                                }
                            }
                        }
                        else if (inudp)
                        {
                            // Check for source port.
                            if (prevkey != NULL && !strcmp(prevkey, "srcport"))
                            {
                                cfg->seq[*seqnum].udp.srcport = (uint16_t) atoi((const char *)ev.data.scalar.value);
                            }

                            // Check for destination port.
                            if (prevkey != NULL && !strcmp(prevkey, "dstport"))
                            {
                                cfg->seq[*seqnum].udp.dstport = (uint16_t) atoi((const char *)ev.data.scalar.value);
                            }
                        }
                        else if (intcp)
                        {
                            // Check for source port.
                            if (prevkey != NULL && !strcmp(prevkey, "srcport"))
                            {
                                cfg->seq[*seqnum].tcp.srcport = (uint16_t) atoi((const char *)ev.data.scalar.value);
                            }

                            // Check for destination port.
                            if (prevkey != NULL && !strcmp(prevkey, "dstport"))
                            {
                                cfg->seq[*seqnum].tcp.dstport = (uint16_t) atoi((const char *)ev.data.scalar.value);
                            }

                            // Check for SYN flag.
                            if (prevkey != NULL && !strcmp(prevkey, "syn"))
                            {
                                cfg->seq[*seqnum].tcp.syn = (!strcmp(lowerstr((char *)ev.data.scalar.value), "true")) ? 1 : 0;
                            }

                            // Check for ACK flag.
                            if (prevkey != NULL && !strcmp(prevkey, "ack"))
                            {
                                cfg->seq[*seqnum].tcp.ack = (!strcmp(lowerstr((char *)ev.data.scalar.value), "true")) ? 1 : 0;
                            }

                            // Check for PSH flag.
                            if (prevkey != NULL && !strcmp(prevkey, "psh"))
                            {
                                cfg->seq[*seqnum].tcp.psh = (!strcmp(lowerstr((char *)ev.data.scalar.value), "true")) ? 1 : 0;
                            }

                            // Check for RST flag.
                            if (prevkey != NULL && !strcmp(prevkey, "rst"))
                            {
                                cfg->seq[*seqnum].tcp.rst = (!strcmp(lowerstr((char *)ev.data.scalar.value), "true")) ? 1 : 0;
                            }

                            // Check for FIN flag.
                            if (prevkey != NULL && !strcmp(prevkey, "fin"))
                            {
                                cfg->seq[*seqnum].tcp.fin = (!strcmp(lowerstr((char *)ev.data.scalar.value), "true")) ? 1 : 0;
                            }

                            // Check for URG flag.
                            if (prevkey != NULL && !strcmp(prevkey, "urg"))
                            {
                                cfg->seq[*seqnum].tcp.urg = (!strcmp(lowerstr((char *)ev.data.scalar.value), "true")) ? 1 : 0;
                            }

                            // TCP cooked Linux socket.
                            if (prevkey != NULL && !strcmp(prevkey, "usetcpsocket"))
                            {
                                cfg->seq[*seqnum].tcp.usetcpsocket = (!strcmp(lowerstr((char *)ev.data.scalar.value), "true")) ? 1 : 0;
                            }
                        }
                        else if (inicmp)
                        {
                            // Check for code.
                            if (prevkey != NULL && !strcmp(prevkey, "code"))
                            {
                                cfg->seq[*seqnum].icmp.code = (uint8_t) atoi((const char *)ev.data.scalar.value);
                            }

                            // Check for type.
                            if (prevkey != NULL && !strcmp(prevkey, "type"))
                            {
                                cfg->seq[*seqnum].icmp.type = (uint8_t) atoi((const char *)ev.data.scalar.value);
                            }
                        }
                        else if (inpayload)
                        {
                            // Check if we're inside the length mapping already.
                            if (inlength)
                            {
                                // Check for min length.
                                if (prevkey != NULL && !strcmp(prevkey, "min"))
                                {
                                    cfg->seq[*seqnum].payload.minlen = (uint16_t) atoi((const char *)ev.data.scalar.value);
                                }

                                // Check for max length.
                                if (prevkey != NULL && !strcmp(prevkey, "max"))
                                {
                                    cfg->seq[*seqnum].payload.maxlen = (uint16_t) atoi((const char *)ev.data.scalar.value);
                                }

                                if (prevkey != NULL && !strcmp(prevkey, "static"))
                                {
                                    cfg->seq[*seqnum].payload.staticdata = (!strcmp(lowerstr((char *)ev.data.scalar.value), "true")) ? 1 : 0;
                                }
                            }
                            else
                            {
                                // Check for exact payload.
                                if (prevkey != NULL && !strcmp(prevkey, "exact"))
                                {
                                    cfg->seq[*seqnum].payload.exact = strdup((const char *)ev.data.scalar.value);
                                }
                            }
                        }
                        else
                        {
                            // Check for other sequence key => values.

                            // Check for send.
                            if (prevkey != NULL && !strcmp(prevkey, "send"))
                            {
                                cfg->seq[*seqnum].send = (!strcmp(lowerstr((char *)ev.data.scalar.value), "true")) ? 1 : 0;
                            }

                            // Check for block.
                            if (prevkey != NULL && !strcmp(prevkey, "block"))
                            {
                                cfg->seq[*seqnum].block = (!strcmp(lowerstr((char *)ev.data.scalar.value), "true")) ? 1 : 0;
                            }

                            // Check for count.
                            if (prevkey != NULL && !strcmp(prevkey, "count"))
                            {
                                cfg->seq[*seqnum].count = strtoull((const char *)ev.data.scalar.value, (char **)ev.data.scalar.value, 0);
                            }

                            // Check for time.
                            if (prevkey != NULL && !strcmp(prevkey, "time"))
                            {
                                cfg->seq[*seqnum].time = strtoull((const char *)ev.data.scalar.value, (char **)ev.data.scalar.value, 0);
                            }

                            // Check for time.
                            if (prevkey != NULL && !strcmp(prevkey, "delay"))
                            {
                                cfg->seq[*seqnum].delay = strtoull((const char *)ev.data.scalar.value, (char **)ev.data.scalar.value, 0);
                            }

                            // Check for max data.
                            if (prevkey != NULL && !strcmp(prevkey, "maxdata"))
                            {
                                cfg->seq[*seqnum].maxdata = strtoull((const char *)ev.data.scalar.value, (char **)ev.data.scalar.value, 0);
                            }

                            // Check for tracking count.
                            if (prevkey != NULL && !strcmp(prevkey, "trackcount"))
                            {
                                cfg->seq[*seqnum].trackcount = (!strcmp(lowerstr((char *)ev.data.scalar.value), "true")) ? 1 : 0;
                            }

                            // Check for threads.
                            if (prevkey != NULL && !strcmp(prevkey, "threads"))
                            {
                                cfg->seq[*seqnum].threads = atoi((const char *)ev.data.scalar.value);
                            }

                            // Check for layer 4 checksum.
                            if (prevkey != NULL && !strcmp(prevkey, "l4csum"))
                            {   
                                cfg->seq[*seqnum].l4csum = (!strcmp(lowerstr((char *)ev.data.scalar.value), "true")) ? 1 : 0;
                            }
                        }
                    }
                    else
                    {
                        // If we're only parsing sequences, break.
                        if (onlyseq)
                        {
                            continue;
                        }

                        // We should be in the global scope. Check for things like the interface.
                        if (prevkey != NULL && !strcmp(prevkey, "interface"))
                        {
                            cfg->interface = strdup((const char *)ev.data.scalar.value);
                        }
                    }
                }

                break;
            
            default:
                break;
        }

        // Check for end of file.
        if (ev.type != YAML_STREAM_END_EVENT)
        {
            yaml_event_delete(&ev);
        }
    } while (ev.type != YAML_STREAM_END_EVENT);

    // Delete token if it isn't already.
    yaml_event_delete(&ev);    

    // Close the YAML parser.
    yaml_parser_delete(&parser);

    // Close config file.
    fclose(fp);

    return 0;
}

/**
 * Clears a sequence.
 * 
 * @param cfg A pointer to the config structure.
 * @param seqnum Which sequence to reset.
 * @return void
 */
void clearsequence(struct config *cfg, int seqnum)
{
    cfg->seq[seqnum].send = 1;
    cfg->seq[seqnum].block = 1;
    cfg->seq[seqnum].count = 0;
    cfg->seq[seqnum].threads = 0;
    cfg->seq[seqnum].time = 0;
    cfg->seq[seqnum].delay = 1000000;

    cfg->seq[seqnum].eth.smac = NULL;
    cfg->seq[seqnum].eth.dmac = NULL;

    cfg->seq[seqnum].ip.srcip = NULL;
    cfg->seq[seqnum].ip.dstip = NULL;
    cfg->seq[seqnum].ip.protocol = NULL;
    cfg->seq[seqnum].ip.tos = 0;
    cfg->seq[seqnum].ip.minttl = 64;
    cfg->seq[seqnum].ip.maxttl = 64;
    cfg->seq[seqnum].ip.csum = 1;

    
    cfg->seq[seqnum].udp.srcport = 0;
    cfg->seq[seqnum].udp.dstport = 0;

    cfg->seq[seqnum].tcp.syn = 0;
    cfg->seq[seqnum].tcp.ack = 0;
    cfg->seq[seqnum].tcp.psh = 0;
    cfg->seq[seqnum].tcp.rst = 0;
    cfg->seq[seqnum].tcp.fin = 0;
    cfg->seq[seqnum].tcp.urg = 0;
    cfg->seq[seqnum].tcp.usetcpsocket = 0;
    
    cfg->seq[seqnum].icmp.code = 0;
    cfg->seq[seqnum].icmp.type = 0;

    cfg->seq[seqnum].l4csum = 1;

    cfg->seq[seqnum].payload.exact = NULL;
    cfg->seq[seqnum].payload.staticdata = 0;
    cfg->seq[seqnum].payload.minlen = 0;
    cfg->seq[seqnum].payload.maxlen = 0;

    // Reset includes.
    for (int i = 0; i < cfg->seq[seqnum].includecount; i++)
    {
        cfg->seq[seqnum].includes[cfg->seq[seqnum].includecount] = NULL;
    }

    // Reset source ranges.
    for (int i = 0; i < cfg->seq[seqnum].ip.rangecount; i++)
    {
        cfg->seq[seqnum].ip.ranges[cfg->seq[seqnum].ip.rangecount] = NULL;
    }
}