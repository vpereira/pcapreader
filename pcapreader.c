#include <pcap.h>
#include <stdio.h>
#include <string.h>
#include <stdlib.h>
#include <ctype.h>
#include <errno.h>
#include <sys/types.h>
#include <sys/socket.h>
#include <netinet/in.h>
#include <arpa/inet.h>
#include <time.h>
#include "bson.h"
#include "mongo.h"

//Mongo stuffs
typedef struct {
  mongo_connection conn[1]; /* ptr */
  mongo_connection_options opts[1];
  mongo_conn_return status;
} MConfiguration;


/* default snap length (maximum bytes per packet to capture) */
#define SNAP_LEN 1518

/* ethernet headers are always exactly 14 bytes [1] */
#define SIZE_ETHERNET 14

/* Ethernet addresses are 6 bytes */
#define ETHER_ADDR_LEN	6

/* Ethernet header */
struct sniff_ethernet {
        u_char  ether_dhost[ETHER_ADDR_LEN];    /* destination host address */
        u_char  ether_shost[ETHER_ADDR_LEN];    /* source host address */
        u_short ether_type;                     /* IP? ARP? RARP? etc */
};

/* IP header */
struct sniff_ip {
        u_char  ip_vhl;                 /* version << 4 | header length >> 2 */
        u_char  ip_tos;                 /* type of service */
        u_short ip_len;                 /* total length */
        u_short ip_id;                  /* identification */
        u_short ip_off;                 /* fragment offset field */
        #define IP_RF 0x8000            /* reserved fragment flag */
        #define IP_DF 0x4000            /* dont fragment flag */
        #define IP_MF 0x2000            /* more fragments flag */
        #define IP_OFFMASK 0x1fff       /* mask for fragmenting bits */
        u_char  ip_ttl;                 /* time to live */
        u_char  ip_p;                   /* protocol */
        u_short ip_sum;                 /* checksum */
        struct  in_addr ip_src,ip_dst;  /* source and dest address */
};
#define IP_HL(ip)               (((ip)->ip_vhl) & 0x0f)
#define IP_V(ip)                (((ip)->ip_vhl) >> 4)

/* TCP header */
typedef u_int tcp_seq;

struct sniff_tcp {
        u_short th_sport;               /* source port */
        u_short th_dport;               /* destination port */
        tcp_seq th_seq;                 /* sequence number */
        tcp_seq th_ack;                 /* acknowledgement number */
        u_char  th_offx2;               /* data offset, rsvd */
#define TH_OFF(th)      (((th)->th_offx2 & 0xf0) >> 4)
        u_char  th_flags;
        #define TH_FIN  0x01
        #define TH_SYN  0x02
        #define TH_RST  0x04
        #define TH_PUSH 0x08
        #define TH_ACK  0x10
        #define TH_URG  0x20
        #define TH_ECE  0x40
        #define TH_CWR  0x80
        #define TH_FLAGS        (TH_FIN|TH_SYN|TH_RST|TH_ACK|TH_URG|TH_ECE|TH_CWR)
        u_short th_win;                 /* window */
        u_short th_sum;                 /* checksum */
        u_short th_urp;                 /* urgent pointer */
};

// udp header
struct sniff_udp {
  u_short udp_srcport;
  u_short udp_destport;
  u_short udp_len;
  u_short udp_sum;
};

char *itoa(int n);

//i know its dirt, but it just have to work for now
char *itoa(int n)
{
	static char retbuf[25];
	sprintf(retbuf, "%d", n);
	return retbuf;
}

void
got_packet(u_char *args, const struct pcap_pkthdr *header, const u_char *packet);


/*
 * dissect/print packet
 */
void
got_packet(u_char *args, const struct pcap_pkthdr *header, const u_char *packet)
{

	static int count = 1;                   /* packet counter */
	
	/* declare pointers to packet headers */
	const struct sniff_ethernet *ethernet;  
	const struct sniff_ip *ip;            
	const struct sniff_tcp *tcp;            
  const struct sniff_udp *udp;
  char mydate[32];
  bson b[1];
  bson_buffer buf[1];
  bson_buffer_init( buf );
  bson_append_new_oid(buf, "_id" );
  memset(mydate,0x00,32);  

	int size_ip;
	int size_tcp;

  MConfiguration *conf = (MConfiguration *) args;  

  count++;
  
  ethernet = (struct sniff_ethernet*)(packet);  
	ip = (struct sniff_ip*)(packet + SIZE_ETHERNET);
	size_ip = IP_HL(ip)*4;
  
  sprintf(mydate,"%u",(unsigned)header->ts.tv_sec); 
  bson_append_string( buf, "timestamp", mydate );
  
  
  bson_append_string(buf,"src",inet_ntoa(ip->ip_src));
  bson_append_string(buf,"dst",inet_ntoa(ip->ip_dst));
	
  
  //determine protocol
	switch(ip->ip_p) {
		case IPPROTO_TCP:
      bson_append_string(buf,"protocol","tcp");      
	    tcp = (struct sniff_tcp*)(packet + SIZE_ETHERNET + size_ip);
	    size_tcp = TH_OFF(tcp)*4;
	
      //i dont care ]:-)
      //if (size_tcp < 20) {
      //  fprintf(stderr,"   * Invalid TCP header length: %u bytes\n", size_tcp);
      //  break;
      //}
      bson_append_string(buf,"src_port",(const char *)itoa(ntohs(tcp->th_sport)));
      bson_append_string(buf,"dst_port",(const char *)itoa(ntohs(tcp->th_dport)));
			break;
		case IPPROTO_UDP:
      bson_append_string(buf,"protocol","udp");      
      udp = (struct sniff_udp *)(packet + SIZE_ETHERNET + size_ip);
      bson_append_string(buf,"src_port",(const char *)itoa(ntohs(udp->udp_srcport)));
      bson_append_string(buf,"dst_port",(const char *)itoa(ntohs(udp->udp_destport)));
			break;
		case IPPROTO_ICMP:
      bson_append_string(buf,"protocol","icmp");      
			break;
		case IPPROTO_IP:
      bson_append_string(buf,"protocol","ip");
			break;
		default:
      bson_append_string(buf,"protocol","unknown");
			break;
	}
  
  bson_from_buffer( b, buf );

  //bson_print(b);

  mongo_insert(conf[0].conn, "alfito.logs", b );
  if(b)
    bson_destroy(b);

  return;
}

int main(int argc, char **argv)
{

  char *read_file = NULL;			
	char errbuf[PCAP_ERRBUF_SIZE];		
	pcap_t *handle;				/* packet capture handle */

	char filter_exp[] = "ip";		/* filter expression */
  struct bpf_program fp;			/* compiled filter program (expression) */  
	int num_packets = 0;			/* number of packets to capture */

  MConfiguration conf;
  
	/* check for capture device name on command-line */
	if (argc == 2) {
		read_file = argv[1];
	}
	else {
		fprintf(stderr, "error: unrecognized command-line options\n\n");
    fprintf(stderr, "usage: %s <pcap-file>\n",argv[0]);
		exit(EXIT_FAILURE);
	}


  strcpy(conf.opts->host , "127.0.0.1" );
  conf.opts->port = 27017;
  conf.status = mongo_connect( conf.conn, conf.opts );
  
  switch (conf.status) {
    case mongo_conn_success: printf( "connection succeeded\n" ); break;
    case mongo_conn_bad_arg: printf( "bad arguments\n" ); return 1;
    case mongo_conn_no_socket: printf( "no socket\n" ); return 1;
    case mongo_conn_fail: printf( "connection failed\n" ); return 1;
    case mongo_conn_not_master: printf( "not master\n" ); return 1;
  }
  
  //DROP DB 
  //mongo_cmd_drop_db(conf.conn, "alfito");
  
  if(!(handle = pcap_open_offline(read_file, errbuf))) {
    perror(errbuf);
    exit(-1);
  }

	/* make sure we're capturing on an Ethernet device */
	if (pcap_datalink(handle) != DLT_EN10MB) {
		fprintf(stderr, "traffic is not from Ethernet\n");
		exit(EXIT_FAILURE);
	}

	/* compile the filter expression */
	if (pcap_compile(handle, &fp, filter_exp, 0, 0) == -1) {
		fprintf(stderr, "Couldn't parse filter %s: %s\n",
		    filter_exp, pcap_geterr(handle));
		exit(EXIT_FAILURE);
	}

	/* apply the compiled filter */
	if (pcap_setfilter(handle, &fp) == -1) {
		fprintf(stderr, "Couldn't install filter %s: %s\n",
		    filter_exp, pcap_geterr(handle));
		exit(EXIT_FAILURE);
	}

	/* now we can set our callback function */
	pcap_loop(handle, num_packets, got_packet, (u_char *)&conf);

	/* cleanup */
	pcap_freecode(&fp);
  pcap_close(handle);  
  mongo_destroy(conf.conn);
  printf( "\nconnection closed\n" );
	printf("\nTschüss.\n");
  
  return 0;
}