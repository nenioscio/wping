#ifdef HAVE_CONFIG_H
#include <config.h>
#else
#include <WPingConfig.h>
#endif

#define _GNU_SOURCE 1

#include <stdio.h>
#include <unistd.h>
#include <fcntl.h>
#include <errno.h>
#include <netdb.h>
#include <string.h>
#include <strings.h>
#include "mongoose.h"
#include <arpa/inet.h>
#include <netinet/in.h>
#include <netinet/ip.h>
/* Not including ip_icmp.h (major issues depending on os)
#include <netinet/ip_icmp.h>*/
#include <sys/socket.h>
#include <poll.h>
#include <stdlib.h>
#include <netinet/in_systm.h>
#include "icmp.h"
#include <time.h>
#include <sys/time.h>

/* wor*/
#ifndef timeradd
#define timeradd(tvp, uvp, vvp)                                         \
        do {                                                            \
                (vvp)->tv_sec = (tvp)->tv_sec + (uvp)->tv_sec;          \
                (vvp)->tv_usec = (tvp)->tv_usec + (uvp)->tv_usec;       \
                if ((vvp)->tv_usec >= 1000000) {                        \
                        (vvp)->tv_sec++;                                \
                        (vvp)->tv_usec -= 1000000;                      \
                }                                                       \
        } while (0)
#endif

#ifdef HAVE_ARPA_INET_H
#include <arpa/inet.h>
#endif

#define ERR_PARAM       "Parameter error"
#define ERR_SOCKET      "Error creating socket"
#define ERR_SETSOCKOPT  "Error setting socket option"
#define ERR_SETNONBLOCK "Error setting O_NONBLOCK"


#define MAX_MTU       2048
#ifndef _AIX
#define CLEAR_MTU        0
#else
#define CLEAR_MTU        1
#endif

#define PACKETSIZE      64
#define ICMPHDRSIZE      8
#define DATASIZE          (PACKETSIZE-ICMPHDRSIZE)

struct ping_packet
{
    union
    {
        icmphdr_t hdr;
        char packet[PACKETSIZE];
    } pkt;
#define hdr pkt.hdr
};

/* ***TODO: use ping_stack for package retriest */
typedef struct ping_stack
{
    struct ping_packet  *ps_packet;
    struct ping_stack   *ps_next;
    struct ping_stack   *ps_prev;
    struct timeval      ps_starttime;
    
    struct timeval      ps_lastsendtime;
    int                 num_sent;
    int                 num_recv;
} ping_stack_t;



static const char *html_form =
  "<html><body>PING example."
  "<form method=\"POST\" action=\"/handle_post_request\">"
  "Target Hostname/IPv4: <input type=\"text\" name=\"dst\" /> <br/>"
  "Timeout: <input type=\"text\" name=\"timeout\" /> <br/>"
  "<input type=\"submit\" />"
  "</form></body></html>";

int globsd = -1;

int set_socket_rcvbuf(int sd, const int val_rcvbuf) {
/* Tests showed that 'disabling the socket buffer on AIX
 *  does break polling on the socket */
#ifndef _AIX
    int orig_rcvbuf, orig_rcvbuf_size;
    if (setsockopt(sd, SOL_SOCKET, SO_RCVBUF, (char *)(&val_rcvbuf), sizeof(val_rcvbuf))!= 0) {
        return errno;
    }
#endif
    return 0;
}

int setup_socket_inet_raw(struct protoent* proto, char **errmsg) {
    const int val = 255;
    const int val_rcvbuf = 0;
    int sd;
    if (proto == NULL) {
        *errmsg = (char *) &ERR_PARAM;
        return -1;
    }
    sd = socket(PF_INET, SOCK_RAW, proto->p_proto);
    if (sd < 0) {
        *errmsg = (char *) &ERR_SOCKET;
        return sd;
    }
    if (setsockopt(sd, IPPROTO_IP, IP_TTL, &val, sizeof(val)) != 0) {
        *errmsg = (char *) &ERR_SETSOCKOPT;
        return -1;
    }
    if (set_socket_rcvbuf(sd, 0) != 0) {
        *errmsg = (char*) &ERR_SETSOCKOPT;
        return -1;
    }
    if (fcntl(sd, F_SETFL, O_NONBLOCK) != 0) {
        *errmsg = (char *) &ERR_SETNONBLOCK;
        return -1;
    }
    return sd;
}

int icmp_pkt_matches(struct ping_packet * pkt1, void* buf2, size_t bytes1, size_t bytes2) {
    unsigned char *ptr;
    struct ip     *ip;
    struct ping_packet *pkt2;

#ifdef _DEBUG
    size_t         i;
    printf("echo request");
    ptr = (unsigned char *) pkt1;
    for (i = 0; i < bytes1; i++) {
		if ( !(i & 15) ) printf("\n%04X:  ", (unsigned int) i);
		printf("%02X ", ((unsigned char*)ptr)[i]);
	}
    printf("\n");

    printf("echo response");
    ptr = (unsigned char *) buf2;
    for (i = 0; i < bytes2; i++) {
		if ( !(i & 15) ) printf("\n%04X:  ", (unsigned int) i);
		printf("%02X ", ((unsigned char*)ptr)[i]);
	}
    printf("\n");
#endif

    ptr      = (unsigned char *) buf2;
    ip       = (struct ip *) buf2;
    ptr     += ip->ip_hl * 4;
    bytes2  -= ip->ip_hl * 4;
    pkt2     = (struct ping_packet *) ptr;
    
    if ( pkt2->hdr.icmp_type == ICMP_DEST_UNREACH ) {
        ptr      = (unsigned char *) pkt2->hdr.icmp_data;
        ip       = (struct ip *) ptr;
        ptr     += ip->ip_hl*4;
        bytes2  -= ip->ip_hl*4;
        pkt2     = (struct ping_packet *) ptr;
    }

#ifdef _DEBUG
    printf("echo response");
    ptr = (unsigned char *) pkt2;
    for (i = 0; i < bytes2; i++) {
		if ( !(i & 15) ) printf("\n%04X:  ", (unsigned int) i);
		printf("%02X ", ((unsigned char*)ptr)[i]);
	}
    printf("\n");
#endif

    /* package shares sequence and if pkt2 is of type ECHOREPLY packages share id  */
    if ( pkt2->hdr.icmp_hun.ih_idseq.icd_seq == pkt2->hdr.icmp_hun.ih_idseq.icd_seq &&
            (pkt1->hdr.icmp_hun.ih_idseq.icd_id == pkt2->hdr.icmp_hun.ih_idseq.icd_id) ) {
        /* further check if message is equal */
        if (!memcmp(pkt1->hdr.icmp_data, pkt2->hdr.icmp_data, DATASIZE)) return 1;
    }
    return 0;
}

int fill_msg(void *msg, int size){
    char *tmp = msg;
    int i;

    if (tmp == NULL) return -1;
    for (i = 0; i <  size; i++) {
        tmp[i] = (char) i +'0';
    }
    return i;
}

unsigned short icmp_calc_checksum(void *b, int len)
{	unsigned short *buf = b;
	unsigned int sum=0;
	unsigned short result;

	for ( sum = 0; len > 1; len -= 2 )
		sum += *buf++;
	if ( len == 1 )
		sum += *(unsigned char*)buf;
	sum = (sum >> 16) + (sum & 0xFFFF);
	sum += (sum >> 16);
	result = ~sum;
	return result;
}

/*--------------------------------------------------------------------*/
/*--- display - present echo info                                  ---*/
/*--------------------------------------------------------------------*/
void display_ping_pkt(void *buf, size_t bytes)
{	size_t i;
	struct ip *ip   = buf;
	icmphdr_t *icmp = buf+ip->ip_hl*4;
    char ipbuf[INET_ADDRSTRLEN];

	printf("----------------\n");
	for ( i = 0; i < bytes; i++ )
	{
		if ( !(i & 15) ) printf("\n%04X:  ", (unsigned int) i);
		printf("%02X ", ((unsigned char*)buf)[i]);
	}
	printf("\n");
	printf("IPv%d: hdr-size=%d pkt-size=%d protocol=%d TTL=%d src=%s ",
		ip->ip_v, ip->ip_hl*4, ntohs(ip->ip_len), ip->ip_p,
		ip->ip_ttl, inet_ntop(AF_INET, &ip->ip_src, ipbuf, INET_ADDRSTRLEN));
	printf("dst=%s\n", inet_ntop(AF_INET, &ip->ip_dst, ipbuf, INET_ADDRSTRLEN));
    printf("ICMP: type[%d/%d] checksum[%d] id[%d] seq[%d] gateway[%s]\n",
        icmp->icmp_type, icmp->icmp_code, ntohs(icmp->icmp_cksum),
        icmp->icmp_hun.ih_idseq.icd_id, icmp->icmp_hun.ih_idseq.icd_seq, 
        inet_ntop(AF_INET, &icmp->icmp_hun.ih_gwaddr, ipbuf, INET_ADDRSTRLEN));
}

int ping(int sd, struct sockaddr_in *ping_addr, char **errmsg, int timeout) {
    struct ping_packet pkt;
    struct sockaddr_in r_addr;
    struct pollfd read_poll, write_poll;
    int seq = 1;
    socklen_t r_addr_len;
    unsigned char buf[MAX_MTU];
    ssize_t readsize, packagesize;
    struct ip *ip;
    struct timeval start_timeval, tmp_timeval, end_timeval;
    icmphdr_t *icmp;
    int retval = 0;

    read_poll.fd       = sd;
    read_poll.events   = POLLRDNORM;
    read_poll.revents  = 0;

    write_poll.fd      = sd;
    write_poll.events  = POLLOUT;
    write_poll.revents = 0;

    r_addr_len         = sizeof(r_addr);

    /* clear socket */
    if (set_socket_rcvbuf(sd, MAX_MTU)!= 0) {
        *errmsg = (char*) &"setsockopt error";
        return -7;
    }
    while ( recvfrom(sd, &pkt, sizeof(pkt), 0, (struct sockaddr*)&r_addr, &r_addr_len) > 0) {
    }

    /* prepare packet */
    bzero(&pkt, sizeof(pkt));
    pkt.hdr.icmp_type        = ICMP_ECHO;
    pkt.hdr.icmp_id  = getpid();
    pkt.hdr.icmp_seq = htons(seq++);
    if (fill_msg(pkt.hdr.icmp_data, DATASIZE) != DATASIZE) return -1;
    pkt.hdr.icmp_cksum = icmp_calc_checksum(&pkt, sizeof(pkt));

    /* send packet */
    if (poll(&write_poll, 1, 100) < 1) return -2;
    if (sendto(sd, &pkt, sizeof(pkt), 0, (struct sockaddr*)ping_addr, sizeof(struct sockaddr_in)) 
        <= 0) {
        *errmsg = (char*) &"send error";
        return -3;
    }

    /* prepare timevals start, end, tmp */
    if (gettimeofday(&start_timeval, NULL) == -1) {
        *errmsg = (char*) &"gettime error";
        return -4;
    }
    tmp_timeval.tv_sec = timeout / 1000;
    tmp_timeval.tv_usec = (timeout % 1000) * 1000;
    timeradd(&start_timeval, &tmp_timeval, &end_timeval);
    /* loop for response/timeout handling */
    while (1) {
        if (gettimeofday(&tmp_timeval, NULL) == -1) {
            *errmsg = (char*) &"gettime error";
            return -4;
        }
        if (timercmp(&tmp_timeval, &end_timeval, >)) {
            *errmsg=(char *)&"timeout icmp";
            retval = -6;
            break;
        }
        /* ***TODO use delta between end_timeval and tmp_timeval if lower that 100 *** */
        if (poll(&read_poll, 1, 100) != 1) {
            continue;
        }
#ifdef _DEBUG
        printf("read_poll.fd=%d\nread_poll.events=%d\nread.poll.revents=%d\n", read_poll.fd, read_poll.events, read_poll.revents);
#endif
        readsize = recvfrom(sd, buf, sizeof(buf), 0, (struct sockaddr*)&r_addr, &r_addr_len);
        if (readsize < 0) {
#ifdef _DEBUG
            printf("recvfrom error(fd=%d, errno=%d): %s\n", sd, errno, strerror(errno));
#endif
            continue;
        }
        if (readsize < (sizeof(pkt) + sizeof(struct ip))) {
            *errmsg=(char *)&"read error";
            retval = -5;
            break;
        } else {
            ip = (struct ip *)buf;
            packagesize = ntohs(ip->ip_len);
            if (readsize < packagesize) {
                 *errmsg=(char *)&"read error";
                retval = -5;
                break;
            }
            printf("package received\nreadsize=%d\npackagesize=%d\nsizeof(pkt)=%d\n",
                readsize, packagesize, sizeof(pkt));
            if (icmp_pkt_matches(&pkt, &buf, sizeof(pkt), packagesize)) {
                icmp = (icmphdr_t *)(buf+ip->ip_hl*4);
#ifdef _DEBUG
                printf("package matched\nreadsize=%d\npackagesize=%d\nsizeof(pkt)=%d\n",
                    readsize, packagesize, sizeof(pkt));
                display_ping_pkt(buf, readsize);
                printf("icmp_type: %d\n", icmp->icmp_type);
#endif
                retval = icmp->icmp_type;
                break;
            } 
#ifdef _DEBUG
            else {
                printf("package didn't match\n");
            }
#endif
        } 
    }
    if (set_socket_rcvbuf(sd, 0)!= 0) {
        *errmsg = (char*) &"setsockopt error";
        return -7;
    }
    return retval;
} 

static int handler(struct mg_connection *conn) {
  char dst[500], timeoutstr[500];
  char *errmsg = NULL;
  char *endptr = NULL;
  const char *accept;
  int  timeout;

  struct hostent *dst_host;
  struct sockaddr_in addr;

  if (strcmp(conn->uri, "/handle_post_request") == 0) {
    // User has submitted a form, show submitted data and a variable value
    // Parse form data. var1 and var2 are guaranteed to be NUL-terminated
    mg_get_var(conn, "dst", dst, sizeof(dst));
    mg_get_var(conn, "timeoutMs", timeoutstr, sizeof(timeoutstr));


    // Send reply to the client, showing submitted form values.
    // POST data is in conn->content, data length is in conn->content_len
    mg_send_header(conn, "Content-Type", "text/plain");
    if ((accept=mg_get_header(conn, "Accept")) != NULL) {
        mg_printf_data(conn,
                        "Accept: %s\n", accept);
    }
    mg_printf_data(conn,
                   "Submitted data: [%.*s]\n"
                   "Submitted data length: %d bytes\n"
                   "Destination: [%s]\n"
                   "Timeout(ms):     [%s]\n",
                   conn->content_len, conn->content,
                   conn->content_len, dst, timeoutstr);

    dst_host = gethostbyname(dst);
    if (dst_host == NULL) {
        mg_printf_data(conn, "Could not resolv: %s, errno: %d\n", dst, errno);
        return MG_REQUEST_PROCESSED;
    }
    bzero(&addr, sizeof(addr));
    addr.sin_family      = dst_host->h_addrtype;
    addr.sin_port        = 0;
    addr.sin_addr.s_addr = *(long*)dst_host->h_addr;

    timeout = strtol(timeoutstr, &endptr, 10);
    if (endptr == NULL) {
        mg_printf_data(conn,
                        "Timeout invalid: %s\n", timeoutstr);
    } else {
        mg_printf_data(conn,
                       "Ping says: %d\n", ping(globsd, &addr, (char **) &errmsg, timeout));
        if (errmsg != NULL) {
            mg_printf_data(conn,
                            "Errmsg was: %s\n", errmsg);
        }
    }
  } else {
    // Show HTML form.
    mg_send_data(conn, html_form, strlen(html_form));
  }

  return MG_REQUEST_PROCESSED;
}

int main(void) {
  struct mg_server *server = mg_create_server(NULL);
  mg_set_option(server, "listening_port", "8080");
  mg_set_request_handler(server, handler);
  char *errmsg;

  if ((globsd = setup_socket_inet_raw(getprotobyname("ICMP"), (char **) &errmsg)) < 0) {
    printf("%s\n", errmsg);
    exit(1);
  }

  printf("Starting on port %s\n", mg_get_option(server, "listening_port"));
  for (;;) {
    mg_poll_server(server, 1000);
  }
  mg_destroy_server(&server);
  return 0;
}
