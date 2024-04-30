#ifdef HAVE_CONFIG_H
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
#include <netinet/in_systm.h>
#include <netinet/ip.h>
/* Not including ip_icmp.h (major issues depending on os)
#include <netinet/ip_icmp.h>*/
#include <sys/socket.h>
#include <poll.h>
#include <stdlib.h>
#include "icmp.h"
#include <time.h>
#include <sys/time.h>
/* add json lib */
#include <jansson.h>
#include <sys/wait.h>
#include <sys/stat.h>
#include <pthread.h>

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

#ifndef timersub
#define timersub(tvp, uvp, vvp)                                         \
    do {                                                                \
        (vvp)->tv_sec = (tvp)->tv_sec - (uvp)->tv_sec;                  \
        (vvp)->tv_usec = (tvp)->tv_usec - (uvp)->tv_usec;               \
        if ((vvp)->tv_usec < 0) {                                       \
            (vvp)->tv_sec--;                                            \
            (vvp)->tv_usec += 1000000;                                  \
        }                                                               \
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
#define CLEAR_MTU        0

#define PACKETSIZE      64
#define ICMPHDRSIZE      8
#define DATASIZE          (PACKETSIZE-ICMPHDRSIZE)

#define WPING_BUFSIZE 8192

struct ping_packet
{
    union
    {
        icmphdr_t hdr;
        char packet[PACKETSIZE];
    } pkt;
#define hdr pkt.hdr
};

/* ***TODO: use ping_stack for package resending */
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
  "<form method=\"POST\" action=\"/ping\">"
  "Target Hostname/IPv4: <input type=\"text\" name=\"dst\" /> <br/>"
  "Timeout (ms): <input type=\"text\" name=\"timeoutms\" /> <br/>"
  "<input type=\"submit\" />"
  "</form></body></html>";

struct str_wping_options{
    char *port;
    char *pidfile;
    int want_daemon;
    int num_threads;
};

struct str_wping_options wping_options;

int globsd = -1;
int exit_flag = 0;
pthread_mutex_t g_lock;

static void signal_handler(int sig_num) {
    signal(sig_num, signal_handler);

    if (sig_num == SIGCHLD) {
        while (waitpid(-1, &sig_num, WNOHANG) > 0) {}
    } else {
        exit_flag = sig_num;
    }
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

    /* ignroe foreign echo requests */
    if ( pkt2->hdr.icmp_type == ICMP_ECHO ) {
        return 0;
    }
    if ( pkt2->hdr.icmp_type == ICMP_DEST_UNREACH || pkt2->hdr.icmp_type == ICMP_TIME_EXCEEDED ) {
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
    if ( pkt1->hdr.icmp_seq == pkt2->hdr.icmp_seq &&
            (pkt1->hdr.icmp_id == pkt2->hdr.icmp_id) ) {
        bytes2 -= ((unsigned char *) pkt2->hdr.icmp_data) - ((unsigned char*) pkt2);
#ifdef _DEBUG
        printf("echo seq and id matching\n");
#endif
        /* further check if message is equal */
        if (bytes2 < DATASIZE) {
            if (pkt2->hdr.icmp_type != ICMP_ECHOREPLY) return 1;
        } else {
            if (!memcmp(pkt1->hdr.icmp_data, pkt2->hdr.icmp_data, DATASIZE)) return 1;
        }
    }
    return 0;
}

int fill_msg(void *msg, struct timeval *start_tv, int size){
    char *tmp = msg;
    int i;
    int datastart = 0;

    if (tmp == NULL) return -1;
    if (start_tv != NULL && sizeof(struct timeval) < size) {
        datastart = sizeof(struct timeval);
        memcpy(msg, start_tv, datastart);
    }
    for (i = datastart; i <  size; i++) {
        tmp[i] = (char) ((i - datastart) % 26) +'A';
    }
    return i;
}

unsigned short icmp_calc_checksum(void *b, int len) {
    unsigned short *buf = b;
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
void display_ping_pkt(void *buf, size_t bytes) {
    size_t i;
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

int ping(struct sockaddr_in *ping_addr, char **errmsg, int *timeout, int *icmp_type, int *icmp_code) {
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
    int sd;

    if ((sd = setup_socket_inet_raw(getprotobyname("ICMP"), (char **) &errmsg)) < 0) {
        return -8;
    }

    read_poll.fd       = sd;
    read_poll.events   = POLLRDNORM;
    read_poll.revents  = 0;

    write_poll.fd      = sd;
    write_poll.events  = POLLOUT;
    write_poll.revents = 0;

    r_addr_len         = sizeof(r_addr);

    /* prepare packet */
    bzero(&pkt, sizeof(pkt));
    pkt.hdr.icmp_type = ICMP_ECHO;
    /* sd number ought to be unique over all threads */
    pkt.hdr.icmp_id = sd;
    pkt.hdr.icmp_seq  = htons(seq++);
    /* we use the timestamp in the packet so prepare start timer here */
    if (gettimeofday(&start_timeval, NULL) == -1) {
        *errmsg = (char*) &"gettime error";
        shutdown(sd, SHUT_RDWR);
        return -4;
    }
    if (fill_msg(pkt.hdr.icmp_data, &start_timeval, DATASIZE) != DATASIZE) {
        *errmsg = (char*) &"Error filiing Message";
        shutdown(sd, SHUT_RDWR);
        return -1;
    }
    pkt.hdr.icmp_cksum = icmp_calc_checksum(&pkt, sizeof(pkt));

    /* send packet */
    if (poll(&write_poll, 1, 100) < 1) return -2;
    if (sendto(sd, &pkt, sizeof(pkt), 0, (struct sockaddr*)ping_addr, sizeof(struct sockaddr_in))
        <= 0) {
        *errmsg = (char*) &"send error";
        shutdown(sd, SHUT_RDWR);
        return -3;
    }

    /* prepare timevals end, tmp */
    tmp_timeval.tv_sec = *timeout / 1000;
    tmp_timeval.tv_usec = (*timeout % 1000) * 1000;
    timeradd(&start_timeval, &tmp_timeval, &end_timeval);
    /* loop for response/timeout handling */
    while (1) {
        if (gettimeofday(&tmp_timeval, NULL) == -1) {
            *errmsg = (char*) &"gettime error";
            shutdown(sd, SHUT_RDWR);
            return -4;
        }
        if (timercmp(&tmp_timeval, &end_timeval, >)) {
            *errmsg=(char *)&"timeout icmp";
            *timeout = -1;
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
        if (readsize < (sizeof(icmphdr_t) + sizeof(struct ip))) {
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
#ifdef _DEBUG
            printf("package received\nreadsize=%ld\npackagesize=%ld\nsizeof(pkt)=%zu\n",
                readsize, packagesize, sizeof(pkt));
#endif
            if (icmp_pkt_matches(&pkt, &buf, sizeof(pkt), packagesize)) {
                icmp = (icmphdr_t *)(buf+ip->ip_hl*4);
#ifdef _DEBUG
                printf("package matched\nreadsize=%ld\npackagesize=%ld\nsizeof(pkt)=%zu\n",
                    readsize, packagesize, sizeof(pkt));
                display_ping_pkt(buf, readsize);
                printf("icmp_type: %d\n", icmp->icmp_type);
#endif
                *icmp_type = icmp->icmp_type;
                *icmp_code = icmp->icmp_code;
                if (gettimeofday(&tmp_timeval, NULL) == -1) {
                    *errmsg = (char*) &"gettime error";
                    shutdown(sd, SHUT_RDWR);
                    return -4;
                }
                timersub(&tmp_timeval, &start_timeval, &end_timeval);
                *timeout = end_timeval.tv_usec / 1000 + end_timeval.tv_sec * 1000;
                retval = 0;
                break;
            }
#ifdef _DEBUG
            else {
                printf("package didn't match\n");
            }
#endif
        }
    }
    shutdown(sd, SHUT_RDWR);
    return retval;
}

/**
 * resolve IPv4 in a threadsave manner in AIX 5+, Solaris, Linux
 * (and possibly others)
 * using gethostbyname variants
 *
 * addr: target result buffer (struct sockaddr_in)
 * hostname: ip definition to resolve
 *
 */
int ipv4_resolv(struct sockaddr_in *addr, const char *hostname) {
    struct hostent *target = NULL;
    int retval = 1;
#if defined(sun) || defined(__sun) || defined(__linux__)
    struct hostent *buf = NULL;
    int h_errnop;

    buf = calloc(1, WPING_BUFSIZE);

    if (!buf) {
        return 0;
    }
#if defined(sun) || defined(__sun)
    target = gethostbyname_r(hostname, buf, (char *)buf + sizeof(struct hostent),
                             WPING_BUFSIZE - sizeof(struct hostent), &h_errnop);

#elif defined(__linux__)
    (void)gethostbyname_r(hostname, buf, (char *)buf + sizeof(struct hostent),
                             WPING_BUFSIZE - sizeof(struct hostent), &target, &h_errnop);
#endif

#else
#ifdef BSD
    if (pthread_mutex_lock(&g_lock) != 0) {
        return 0;
    }
#endif
    target = gethostbyname(hostname);
#ifdef BSD
    if (pthread_mutex_unlock(&g_lock) != 0) {
        return 0;
    }
#endif
#endif

    /* extract result */
    if(target != NULL) {
        bzero(addr, sizeof(struct sockaddr_in));
        addr->sin_family      = target->h_addrtype;
        addr->sin_port        = 0;
        addr->sin_addr.s_addr = *(long*)target->h_addr;
    } else {
        retval = 0;
    }

#if defined(sun) || defined(__sun) || defined(__linux__)
        free(buf);
#endif

    return retval;

}


static int handler(struct mg_connection *conn, enum mg_event ev) {
    char dst[500], timeoutstr[500], buf[500];
    char *errmsg = NULL;
    char *endptr = NULL;
    char *jsonout = NULL;
    const char *accept;
    int  timeout;
    int  icmp_type;
    int  icmp_code;
    int  retval;
    int  alive = 1;
    int  wantjson = 0;

    struct hostent *dst_host;
    struct sockaddr_in addr;
    json_t *jsonoutdata;

#ifdef _DEBUG
    printf("mg_event %d\n", ev);
#endif

    if (ev != MG_REQ_BEGIN) {
        return MG_TRUE;
    }
    if (strcmp(conn->uri, "/ping") == 0) {
        // User has submitted a form, show submitted data and a variable value
        // Parse form data. var1 and var2 are guaranteed to be NUL-terminated
        mg_get_var(conn, "dst", dst, sizeof(dst));
        mg_get_var(conn, "timeoutMs", timeoutstr, sizeof(timeoutstr));

        // Check for json request and store in flag
        accept=mg_get_header(conn, "Accept");
        if ( (accept != NULL ) && (strstr(accept, "application/json") != NULL)) {
            wantjson = 1;
        }
        if (wantjson){
            mg_send_header(conn, "Content-Type", "application/json");
        } else {
            mg_send_header(conn, "Content-Type", "text/plain");
#ifdef _DEBUG
        if (accept != NULL) {
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
#endif
        }


        if (!ipv4_resolv(&addr, dst)) {
            if (wantjson) {
                snprintf(buf, sizeof(buf) -1, "Could not resolv: %s, errno: %d", dst, errno);
                jsonoutdata = json_pack("{sbss}", "status", alive, "status_message",
                                        buf);
                jsonout    = json_dumps(jsonoutdata, 1024);
                mg_send_data(conn, jsonout, strlen(jsonout));
                json_decref(jsonoutdata);
                free(jsonout);
            } else {
                mg_printf_data(conn, "Could not resolv: %s, errno: %d\n", dst, errno);
            }
            return MG_REQUEST_PROCESSED;
        }

        timeout = strtol(timeoutstr, &endptr, 10);
        if (endptr == NULL) {
            mg_printf_data(conn,
                            "Timeout invalid: %s\n", timeoutstr);
        } else {
            icmp_type = icmp_code = 0;
            retval = ping(&addr, (char **) &errmsg, &timeout, &icmp_type, &icmp_code);
            if (retval != 0 || icmp_type != 0) {
                alive = 0;
            }
            if ( wantjson ) {
                if (errmsg == NULL) {
                    errmsg = "";
                }
                jsonoutdata = json_pack("{sbsssisisi}", "status", alive, "status_message",
                                        errmsg, "icmp_type", icmp_type, "icmp_code", icmp_code,
                                        "response_time", timeout);
                jsonout    = json_dumps(jsonoutdata, 1024);
                mg_send_data(conn, jsonout, strlen(jsonout));
                json_decref(jsonoutdata);
                free(jsonout);
            } else {
                mg_printf_data(conn,
                               "Destination alive: %d\n"
                               "Icmp_response_type: %d\n"
                               "Icmp_response_code: %d\n"
                               "Icmp_response_time: %d\n",
                                alive, icmp_type, icmp_code, timeout);
                if (errmsg != NULL) {
                    mg_printf_data(conn,
                                    "Errmsg was: %s\n", errmsg);
                }
            }
        }
    } else {
        // Show HTML form.
        mg_send_data(conn, html_form, strlen(html_form));
    }

    return MG_REQUEST_PROCESSED;
}

void parse_args(int argc, char*argv[], struct str_wping_options *target) {
    int c;

    /* defaults */
    target->port = NULL;
    target->pidfile = NULL;
    target->want_daemon = 0;
    target->num_threads = 0;

    while (1) {
        c = getopt(argc, argv, "hdp:f:t:");

        if (c == -1) {
            break;
        }

        switch (c) {
            case 'd':
                target->want_daemon = 1;
                break;
            case 'p':
                target->port = strdup(optarg);
                break;
            case 'f':
                target->pidfile = strdup(optarg);
                break;
            case 't':
                target->num_threads = atol(optarg);
                break;
            case 'h':
            default:
                printf( "Usage: %s [-d] [-p <port>] [-f <pidfile>] [-t <Number of threads>]\n"
                        "\t-d\t\t\tStart deaemon (background mode)\n"
                        "\t-p <port>\t\tport to bind onto\n"
                        "\t-f <pidfile>\t\tpidfile to create\n"
                        "\t-t <Number of threads>\tDefault mode does not\n"
                        "\t-h\t\t\tThis message\n\n", argv[0]);
                exit(-1);
        }
    }
    if (target->port == NULL) {
        target->port = strdup("8080");
    }
    if (target->pidfile == NULL) {
        target->pidfile = strdup("/var/run/wping/wping.pid");
    }
}

void clean_options(struct str_wping_options *target) {
    if (target->port != NULL) {
        free(target->port);
    }
    if (target->pidfile != NULL) {
        free(target->pidfile);
    }
}

static void *serve(void *server) {
    while (exit_flag == 0) {
        mg_poll_server(server, 1000);
    }
    return NULL;
}

int main(int argc, char *argv[]) {
    char *errmsg;
    char buf[WPING_BUFSIZE];


    parse_args(argc, argv, &wping_options);

    /* test socket first */
    if ((globsd = setup_socket_inet_raw(getprotobyname("ICMP"), (char **) &errmsg)) < 0) {
        printf("%s\n", errmsg);
        exit(1);
    }

    if (wping_options.want_daemon) {
        struct stat pid_file;
        int pid_file_fd;
        size_t write_len;
        int null_fd;
        pid_t pid;


        pid = fork();

        if (pid < 0) {
            printf("%s: Error forking daemon\n", argv[0]);
            exit(1);
        }
        if (pid == 0) {

            umask(0);
            pid_t sid;
            sid = setsid();
            if (sid < 0) {
                //printf("%s: Error calling setsid()\n", argv[0]);
                exit(1);
            }

            if ((chdir("/")) < 0) {
                //printf("%s: Could not change directory\n", argv[0]);
                exit(1);
            }

            if (pthread_mutex_init(&g_lock, 0) != 0) {
                exit(1);
            }

            // Cleanup FDs
            close(STDIN_FILENO);
            close(STDOUT_FILENO);
            close(STDERR_FILENO);
            null_fd = open("/dev/null", O_RDWR);
            dup2(null_fd,STDIN_FILENO);
            dup2(null_fd,STDOUT_FILENO);
            dup2(null_fd,STDERR_FILENO);

            signal(SIGTERM, signal_handler);
            signal(SIGINT, signal_handler);
            signal(SIGCHLD, signal_handler);

            /* create pid file */
            pid_file_fd = open(wping_options.pidfile, O_CREAT|O_EXCL|O_WRONLY, 00644);
            if (pid_file_fd == -1) {
                exit(1);
            }
            pid = getpid();
            write_len = snprintf(buf, sizeof(buf)-1, "%d\n", pid);
            if (write_len != write(pid_file_fd, buf, write_len)) {
                exit(1);
            }
            close(pid_file_fd);
        } else {
            int status = 0;

            /* wait for pidfile / or child exit */
            while (stat(wping_options.pidfile, &pid_file) != 0) {
                if (waitpid(-1, &status, WNOHANG) == pid) {
                    printf("%s: It's dead jim. Initialization failed.\n", argv[0]);
                    exit(1);
                }
                sleep(1);
            }
            clean_options(&wping_options);
            exit(0);
        }
    } else {
        /* reroute sigint only for valgrind */
        signal(SIGINT, signal_handler);
    }

    if (wping_options.num_threads < 1) {
        struct mg_server *server = mg_create_server(&globsd, handler);
        mg_set_option(server, "listening_port", wping_options.port);

    #ifdef _DEBUG
        printf("Starting on port %s\n", mg_get_option(server, "listening_port"));
    #endif
        while (exit_flag == 0) {
            mg_poll_server(server, 1000);
        }
        mg_destroy_server(&server);
    } else {
        struct mg_server **mg_servers = NULL;
        close(globsd);

        mg_servers = calloc(wping_options.num_threads, sizeof(struct mg_server *));
        for (int i = 0; i < wping_options.num_threads; i ++) {
            mg_servers[i] = mg_create_server(NULL, handler);
            if (i == 0) {
                mg_set_option(mg_servers[i], "listening_port", wping_options.port);
            } else {
                mg_set_listening_socket(mg_servers[i], mg_get_listening_socket(mg_servers[0]));
            }
            mg_start_thread(serve,  mg_servers[i]);
        }
        while (exit_flag == 0) {
            sleep(1);
        }
        for (int i = 0; i < wping_options.num_threads; i ++) {
            mg_destroy_server(&mg_servers[i]);
        }
    }

    if (wping_options.want_daemon) {
        unlink(wping_options.pidfile);
    }
    clean_options(&wping_options);
    pthread_mutex_destroy(&g_lock);
    return 0;
}
