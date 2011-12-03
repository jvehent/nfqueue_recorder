/*! netfilter_queue.c
 *
 \brief test file
 \author julien vehent
 \date 20111203
 \code gcc -Wall -o nfqueue_recorder nfqueue_recorder.c -lnetfilter_queue -lpcap
 *
 */
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>
#include <pcap.h>
#include <time.h>
#include <getopt.h>
#include <linux/tcp.h>
#include <linux/ip.h>
#include <linux/udp.h>
#include <sys/socket.h>
#include <netinet/in.h>
#include <arpa/inet.h>
#include <linux/netfilter.h>        /* for NF_ACCEPT */
#include <libnetfilter_queue/libnetfilter_queue.h>

#define BUFSIZE 2048
// pcap file descriptor
pcap_dumper_t *p_output;
int use_pcap = 0;

/* returns packet id */
static u_int32_t print_pkt (struct nfq_data *tb)
{
    int id = 0;
    struct nfqnl_msg_packet_hdr *ph;
    u_int32_t mark,ifi;
    int ret;
    char *nf_packet;

    ph = nfq_get_msg_packet_hdr(tb);
    if (ph){
        id = ntohl(ph->packet_id);
        printf("hw_protocol=0x%04x hook=%u id=%u ",
            ntohs(ph->hw_protocol), ph->hook, id);
    }

    mark = nfq_get_nfmark(tb);
    if (mark)
        printf("mark=%u ", mark);

    ifi = nfq_get_indev(tb);
    if (ifi)
        printf("indev=%u ", ifi);

    ifi = nfq_get_outdev(tb);
    if (ifi)
        printf("outdev=%u ", ifi);

    ret = nfq_get_payload(tb, &nf_packet);
    if ((ret >= 0)){
        printf("payload_len=%d bytes", ret);
            fputc('\n', stdout);
        }

    // parse the packet headers
    struct iphdr *iph = ((struct iphdr *) nf_packet);

    // Computing IP address translation from 32 bits words to 4*8bits decimal
    /* NOTE ON THE LENGTHS
    all lengths used in headers are specified in 32bits words
    thus, to print the size in bytes, we need to multiply this value by 4
    */

    // display IP HEADERS : ip.h line 45
    // ntohs convert short unsigned int, ntohl do the same for long unsigned int
    fprintf(stdout, "IP{v=%u; ihl=%u; tos=%u; tot_len=%u; id=%u; ttl=%u; protocol=%u; "
        ,iph->version, iph->ihl*4, iph->tos, ntohs(iph->tot_len), ntohs(iph->id), iph->ttl, iph->protocol);

    char *saddr = inet_ntoa(*(struct in_addr *)&iph->saddr);
    fprintf(stdout,"saddr=%s; ",saddr);

    char *daddr = inet_ntoa(*(struct in_addr *)&iph->daddr);
    fprintf(stdout,"daddr=%s}\n",daddr);

    // if protocol is tcp
    if (iph->protocol == 6){
        // extract tcp header from packet
        /* Calculate the size of the IP Header. iph->ihl contains the number of 32 bit
        words that represent the header size. Therfore to get the number of bytes
        multiple this number by 4 */
        struct tcphdr *tcp = ((struct tcphdr *) (nf_packet + (iph->ihl << 2)));
    
        /* Calculate the size of the TCP Header. tcp->doff contains the number of 32 bit
        words that represent the header size. Therfore to get the number of bytes
        multiple this number by 4 */
        //int tcphdr_size = (tcp->doff << 2); 

        /* to print the TCP headers, we access the structure defined in tcp.h line 89
        and convert values from hexadecimal to ascii */
        fprintf(stdout, "TCP{sport=%u; dport=%u; seq=%u; ack_seq=%u; flags=u%ua%up%ur%us%uf%u; window=%u; urg=%u}\n",
            ntohs(tcp->source), ntohs(tcp->dest), ntohl(tcp->seq), ntohl(tcp->ack_seq)
            ,tcp->urg, tcp->ack, tcp->psh, tcp->rst, tcp->syn, tcp->fin, ntohs(tcp->window), tcp->urg_ptr);
    }

    // if protocol is udp
    if(iph->protocol == 17){
        struct udphdr *udp = ((struct udphdr *) (nf_packet + (iph->ihl << 2)));
        fprintf(stdout,"UDP{sport=%u; dport=%u; len=%u}\n",
            ntohs(udp->source), ntohs(udp->dest), udp->len);
    }

    fprintf(stdout,"\n");

    return id;
}

static u_int32_t record_pkt (struct nfq_data *tb){

    /*! create pcap specific header
     */
    struct pcap_pkthdr phdr;

    /*! init capture time
     */
    static struct timeval t;
    memset (&t, 0, sizeof(struct timeval));
    gettimeofday(&t, NULL);
    phdr.ts.tv_sec = t.tv_sec;
    phdr.ts.tv_usec = t.tv_usec;

    /*! populate pcap struct with packet headers
     */
    char *nf_packet;
    phdr.caplen = nfq_get_payload(tb,&nf_packet);
    phdr.len = phdr.caplen;

    /*! dump packet data to the file */
    pcap_dump((u_char *)p_output, &phdr, (const u_char *)nf_packet);

    return 0;
}


static int cb(struct nfq_q_handle *qh, struct nfgenmsg *nfmsg,
          struct nfq_data *nfa, void *data)
{
    u_int32_t id = print_pkt(nfa);
    if(use_pcap == 1)
        record_pkt(nfa);

    return nfq_set_verdict(qh, id, NF_ACCEPT, 0, NULL);
}

int main(int argc, char **argv)
{
    struct nfq_handle *h;
    struct nfq_q_handle *qh;
    struct nfnl_handle *nh;
    int fd;
    int rv;
    int argument;
    char buf[BUFSIZE];
    char *pcap_destination;
    pcap_t *pd;

    /*! process arguments
     */
    while ( -1 != (argument = getopt (argc, argv, "o:h")))
    {
        switch (argument)
        {
            case 'o' :
                pcap_destination = (char *) malloc(strlen(optarg) * sizeof(char));
                memcpy(pcap_destination,optarg,strlen(optarg));
                fprintf(stdout,"pcap recording into %s\n",pcap_destination);
                use_pcap = 1;
                break;
            case 'h':
                fprintf(stdout,"nfqueue_recorder: record/display traffic passing through a netfilter queue\n\n"
                    "-h: this help\n"
                    "-o <file> : record in pcap <file>\n"
                    "\nroute traffic to it using the NFQUEUE target\n"
                    "\tiptables -I INPUT -p tcp --dport 443 -j NFQUEUE\n"
                    "\tiptables -I FORWARD -j NFQUEUE\n"
                    "\nex: ./nfqueue_recorder -o traffic.pcap\n");
                return 0;
            default:
                fprintf(stdout,"use -h for help\n");
                return -1;
        }
    }

    /*! open dump file
    * using DLT_RAW because iptables does not give us datalink layer
    */
    if(use_pcap == 1){
        fprintf(stdout,"opening pcap file at %s\n",pcap_destination);
        pd = pcap_open_dead(DLT_RAW, BUFSIZE);
        p_output = pcap_dump_open(pd,pcap_destination);
        if (!p_output){
            fprintf(stderr, "error while opening pcap file\n");
            exit(1);
        }
    }

    printf("opening library handle\n");
    h = nfq_open();
    if (!h) {
        fprintf(stderr, "error during nfq_open()\n");
        exit(1);
    }

    printf("unbinding existing nf_queue handler for AF_INET (if any)\n");
    if (nfq_unbind_pf(h, AF_INET) < 0) {
        fprintf(stderr, "error during nfq_unbind_pf()\n");
        exit(1);
    }

    printf("binding nfnetlink_queue as nf_queue handler for AF_INET\n");
    if (nfq_bind_pf(h, AF_INET) < 0) {
        fprintf(stderr, "error during nfq_bind_pf()\n");
        exit(1);
    }

    printf("binding this socket to queue '0'\n");
    qh = nfq_create_queue(h,  0, &cb, NULL);
    if (!qh) {
        fprintf(stderr, "error during nfq_create_queue()\n");
        exit(1);
    }

    printf("setting copy_packet mode\n");
    if (nfq_set_mode(qh, NFQNL_COPY_PACKET, 0xffff) < 0) {
        fprintf(stderr, "can't set packet_copy mode\n");
        exit(1);
    }

    nh = nfq_nfnlh(h);
    fd = nfnl_fd(nh);

    while ((rv = recv(fd, buf, sizeof(buf), 0)) && rv >= 0) {
        printf("-- New packet received --\n");

        nfq_handle_packet(h, buf, rv);
    }

    printf("unbinding from queue 0\n");
    nfq_destroy_queue(qh);

#ifdef INSANE
    /* normally, applications SHOULD NOT issue this command, since
     * it detaches other programs/sockets from AF_INET, too ! */
    printf("unbinding from AF_INET\n");
    nfq_unbind_pf(h, AF_INET);
#endif

    printf("closing library handle\n");
    nfq_close(h);

    exit(0);
}
