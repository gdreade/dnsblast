
#include "dnsblast.h"

#define NANOS_PER_SECOND 1000000000ULL

/* this needs the leading dot */
static const char * domain_name = DEFAULT_DOMAIN;

static int
get_sock(const char * const host, const char * const port,
         struct addrinfo ** const ai_ref);

static unsigned long long
get_nanoseconds(void)
{
    struct timeval tv;
    gettimeofday(&tv, NULL);

    return tv.tv_sec * 1000000000LL + tv.tv_usec * 1000LL;
}

static void
clear_context(Context * const context) {
  unsigned int i;

  for (i = 0; i < context->senders_count; i++) {
    if (context->sock_array[i] >= 0) {
      close(context->sock_array[i]);
    }
    if (context->ai_array[i] != NULL) {
      freeaddrinfo(context->ai_array[i]);
    }
  }
  free(context->pollfds);
  free(context->ai_array);
  free(context->sock_array);
}

static int
init_context(Context * const context,
	     const char *host,
	     const char *port,
	     const in_addr_t lowaddr,
	     const in_addr_t highaddr,
	     const _Bool fuzz)
{
    const unsigned long long now = get_nanoseconds();
    unsigned int i;
    uint32_t lowNum, highNum;

    *context = (Context) {
        .received_packets = 0UL, .sent_packets = 0UL,
        .last_status_update = now, .startup_date = now,
	.senders_count = 0, .current_sender = 0, .fuzz = fuzz, .sending = 1
    };

    DNS_Header * const question_header = (DNS_Header *) context->question;
    *question_header = (DNS_Header) {
        .flags = htons(FLAGS_OPCODE_QUERY | FLAGS_RECURSION_DESIRED),
        .qdcount = htons(1U), .ancount = 0U, .nscount = 0U, .arcount = 0U
    };

    lowNum = ntohl(lowaddr);
    highNum = ntohl(highaddr);
    if ((lowNum == 0) && (highNum == 0)) {
        context->senders_count = 1;
    } else {
        if (lowNum <= highNum) {
	    context->senders_count = highNum - lowNum + 1;
	} else {
	    fprintf(stderr, "The second IP from the -R flag must not be "
		    "smaller than the first IP\n");
	    exit(EXIT_FAILURE);
	}
    }

    context->sock_array = malloc(context->senders_count * sizeof(int));
    if (context->sock_array == NULL) {
        fprintf(stderr, "failed to allocate memory for %d file descriptors", 
		context->senders_count);
	exit(EXIT_FAILURE);
    }
    for (i=0; i < context->senders_count; i++) {
      context->sock_array[i] = -1;
    }

    context->ai_array =
      malloc(context->senders_count * sizeof(struct addrinfo *));
    if (context->ai_array == NULL) {
        fprintf(stderr,
                "failed to allocate memory for %d addrinfo struct pointers", 
                context->senders_count);
	exit(EXIT_FAILURE);
    }
    memset(context->ai_array, 0,
	   context->senders_count * sizeof(struct addrinfo *));

    context->pollfds = malloc(context->senders_count * sizeof(struct pollfd));
    if (context->pollfds == NULL) {
        fprintf(stderr, 
		"failed to allocate memory for %d pollfd structs",
		context->senders_count);
	exit(EXIT_FAILURE);
    }
    for (i = 0; i < context->senders_count; i++) {
        context->pollfds[i].fd = -1;
    }
    
    for (i = 0; i < context->senders_count; i++) {
        context->sock_array[i] = get_sock(host, port, &(context->ai_array[i]));
	if (context->sock_array[i] == -1) {
	    fprintf(stderr, "failed to get socket %d: %s\n", i,
		    strerror(errno));
	    exit(EXIT_FAILURE);
	}

	if (context->senders_count > 1) {
	    /* bind to a specific IP */
	    in_addr_t addr = htonl(lowNum);

	    struct sockaddr_in baddr;
	    memset((char *)&baddr, 0, sizeof(baddr));
	    baddr.sin_family = AF_INET;
	    baddr.sin_addr.s_addr = htonl(lowNum);
	    baddr.sin_port = htons(0);

	    if (bind(context->sock_array[i], (struct sockaddr *) &baddr,
		     sizeof(baddr)) < 0) {
	        struct in_addr iaddr;
		iaddr.s_addr = addr;
		fprintf(stderr, "failed to bind to %s: %s\n", inet_ntoa(iaddr),
			strerror(errno));
		exit(EXIT_FAILURE);
	    }
	}

	lowNum++;
    }

    return 0;
}

static int
find_name_component_len(const char *name)
{
    int name_pos = 0;

    while (name[name_pos] != '.' && name[name_pos] != 0) {
        if (name_pos >= UCHAR_MAX) {
            return EOF;
        }
        name_pos++;
    }
    return name_pos;
}

static int
encode_name(unsigned char ** const encoded_ptr, size_t encoded_size,
            const char * const name)
{
    unsigned char *encoded = *encoded_ptr;
    const char    *name_current = name;
    int            name_current_pos;

    assert(encoded_size > (size_t) 0U);
    encoded_size--;
    for (;;) {
        name_current_pos = find_name_component_len(name_current);
        if (name_current_pos == EOF ||
            encoded_size <= (size_t) name_current_pos) {
            return -1;
        }
        *encoded++ = (unsigned char) name_current_pos;
        memcpy(encoded, name_current, name_current_pos);
        encoded_size -= name_current_pos - (size_t) 1U;
        encoded += name_current_pos;
        if (name_current[name_current_pos] == 0) {
            break;
        }
        name_current += name_current_pos + 1U;
    }
    *encoded++ = 0;
    *encoded_ptr = encoded;

    return 0;
}

static int
fuzz(unsigned char * const question, const size_t packet_size)
{
    int p = REFUZZ_PROBABILITY;

    do {
        question[rand() % packet_size] = rand() % 0xff;
    } while (rand() < p && (p = p / 2) > 0);

    return 0;
}

static int
blast(Context * const context, const char * const name, const uint16_t type)
{
    unsigned char * const question = context->question;
    DNS_Header    * const question_header = (DNS_Header *) question;
    unsigned char * const question_data = question + sizeof *question_header;
    const size_t          sizeof_question_data =
        sizeof question - sizeof *question_header;
    int sock;
    struct addrinfo *ai;

    question_header->id = context->id++;
    unsigned char *msg = question_data;
    assert(sizeof_question_data > (size_t) 2U);
    encode_name(&msg, sizeof_question_data - (size_t) 2U, name);
    PUT_HTONS(msg, type);
    PUT_HTONS(msg, CLASS_IN);
    const size_t packet_size = (size_t) (msg - question);

    if (context->fuzz != 0) {
        fuzz(question, packet_size);
    }

    if ((context->current_sender) >= (context->senders_count)) {
        context->current_sender = 0;
    }

    sock = context->sock_array[context->current_sender];
    ai = context->ai_array[context->current_sender];

    while (sendto(sock, question, packet_size, 0, ai->ai_addr, ai->ai_addrlen)
           != (ssize_t) packet_size) {
        if (errno != EAGAIN && errno != EINTR) {
            perror("sendto");
            exit(EXIT_FAILURE);
        }
    }
    context->sent_packets++;

    if (context->senders_count > 1) {
        context->current_sender += 1;
    }

    return 0;
}

static void
usage(void) {
  fprintf(stderr,
	  "\nUsage:\n"
	  "\tdnsblast [-Fn] [-c <count>] [-d <domain_name>] [-p <port>]\n"
	  "\t\t[-r <rate>] [-R <lowIP:highIP>] <host>\n");
  fprintf(stderr, 
	  "\twhere:\n"
	  "\t\t-h\t\tPrint this message\n"
	  "\t\t-F\t\tUse fuzzing\n"
	  "\t\t-c <count>\tQuery count (default is MAX_INT)\n"
	  "\t\t-d <domain_name>\n"
	  "\t\t\t\tAll queries will be for names under the\n"
	  "\t\t\t\tspecified domain (must begin with a dot).\n"
	  "\t\t\t\tThe default is \"%s\"\n"
	  "\t\t-n\t\tDo not wait to receive return packets.\n"
	  "\t\t-p <port>\tdestination port number or name\n"
	  "\t\t-r <rate>\trate in packets per second\n"
	  "\t\t-R <lowIP>:<highIP>\tspecify a range of IPs from\n"
	  "\t\t\t\twhich packets should be sent\n"
	  "\tand:\n"
	  "\t\t<host>\t\tIP or FQDN\n",
	  DEFAULT_DOMAIN);
    exit(EXIT_SUCCESS);
}

static struct addrinfo *
resolve(const char * const host, const char * const port)
{
    struct addrinfo *ai, hints;

    memset(&hints, 0, sizeof hints);
    hints = (struct addrinfo) {
        .ai_family = AF_UNSPEC, .ai_flags = 0, .ai_socktype = SOCK_DGRAM,
        .ai_protocol = IPPROTO_UDP
    };
    const int gai_err = getaddrinfo(host, port, &hints, &ai);
    if (gai_err != 0) {
        fprintf(stderr, "[%s:%s]: [%s]\n", host, port, gai_strerror(gai_err));
        exit(EXIT_FAILURE);
    }
    return ai;
}

static int
get_random_name(char * const name, size_t name_size)
{
    const char charset_alnum[36] = "abcdefghijklmnopqrstuvwxyz0123456789";

    size_t random_char_count = 4;
    size_t needed = random_char_count + strlen(domain_name) + 1;

    assert(name_size > needed);
    const int r1 = rand(), r2 = rand();
    name[0] = charset_alnum[(r1) % sizeof charset_alnum];
    name[1] = charset_alnum[(r1 >> 16) % sizeof charset_alnum];
    name[2] = charset_alnum[(r2) % sizeof charset_alnum];
    name[3] = charset_alnum[(r2 >> 16) % sizeof charset_alnum];

    char * const p = name + random_char_count;
    strcpy(p, domain_name);

    return 0;
}

static uint16_t
get_random_type(void)
{
    const size_t weighted_types_len =
        sizeof weighted_types / sizeof weighted_types[0];
    size_t       i = 0U;
    const int    rnd = rand();
    int          pos = RAND_MAX;

    do {
        pos -= weighted_types[i].weight;
        if (rnd > pos) {
            return weighted_types[i].type;
        }
    } while (++i < weighted_types_len);

    return weighted_types[rand() % weighted_types_len].type;
}

static int
get_sock(const char * const host, const char * const port,
         struct addrinfo ** const ai_ref)
{
    int flag = 1;
    int sock;

    *ai_ref = resolve(host, port);
    sock = socket((*ai_ref)->ai_family, (*ai_ref)->ai_socktype,
                  (*ai_ref)->ai_protocol);
    if (sock == -1) {
        return -1;
    }
    setsockopt(sock, SOL_SOCKET, SO_RCVBUFFORCE,
               &(int[]) { MAX_UDP_BUFFER_SIZE }, sizeof (int));
    setsockopt(sock, SOL_SOCKET, SO_SNDBUFFORCE,
               &(int[]) { MAX_UDP_BUFFER_SIZE }, sizeof (int));
#if defined(IP_PMTUDISC_OMIT)
    setsockopt(sock, IPPROTO_IP, IP_MTU_DISCOVER,
               &(int[]) { IP_PMTUDISC_OMIT }, sizeof (int));
#elif defined(IP_MTU_DISCOVER) && defined(IP_PMTUDISC_DONT)
    setsockopt(sock, IPPROTO_IP, IP_MTU_DISCOVER,
               &(int[]) { IP_PMTUDISC_DONT }, sizeof (int));
#elif defined(IP_DONTFRAG)
    setsockopt(sock, IPPROTO_IP, IP_DONTFRAG, &(int[]) { 0 }, sizeof (int));
#endif
#if defined(IP_TRANSPARENT)
    setsockopt(sock, SOL_IP, IP_TRANSPARENT, &(int[]) { 1 }, sizeof (int));
#endif
#if defined(IP_FREEBIND)
    setsockopt(sock, SOL_IP, IP_FREEBIND, &(int[]) { 1 }, sizeof (int));
#endif

    assert(ioctl(sock, FIONBIO, &flag) == 0);

    return sock;
}

/**
 * Receive up to one packet per socket and throw them away.
 *
 * timeout is the maximum number of milliseconds that this call will
 * wait for an incoming packet
 *
 * Returns the number of packets received
 */
static int
receive(Context * const context, int timeout)
{
    unsigned char buf[MAX_UDP_DATA_SIZE];

    unsigned i;
    int ready;
    nfds_t pollcount = 0;
    int packets = 0;
    for (i=0; i < context->senders_count; i++) {
      int fd = context->sock_array[i];
      if (fd >= 0) {
	context->pollfds[pollcount].fd = fd;
	context->pollfds[pollcount].events = POLLIN;
	context->pollfds[pollcount].revents = 0;
	pollcount++;
      }
    }

    if (pollcount > 0) {
      ready = poll(context->pollfds, pollcount, timeout);
      if (ready > 0) {
	for (i=0; i<pollcount; i++) {
	  if (context->pollfds[i].revents & POLLIN) {
	    ssize_t bytes = recv(context->pollfds[i].fd, buf, sizeof(buf), 0);
	    if (bytes >= 0) {
	      context->received_packets++;
	      packets++;
	    } else if ((errno != EAGAIN)
		       && (errno != EWOULDBLOCK)
		       && (errno != EINTR)) {
	      perror("recv");
	      exit(EXIT_FAILURE);
	    }
	  }
	}
      } else if (ready < 0) {
	if ((errno != EAGAIN) && (errno != EWOULDBLOCK) && (errno != EINTR)) {
	  perror("poll");
	  exit(EXIT_FAILURE);
	}
      }
    }
    
    return packets;
}

static int
update_status(const Context * const context)
{
    const unsigned long long now = get_nanoseconds();
    const unsigned long long elapsed = now - context->startup_date;
    unsigned long long rate =
        (context->received_packets * NANOS_PER_SECOND) / elapsed;
    if (rate > context->pps) {
        rate = context->pps;
    }
    printf("Sent: [%lu] - Received: [%lu] - Reply rate: [%llu pps] - "
           "Ratio: [%.2f%%]  \r",
           context->sent_packets, context->received_packets, rate,
           (double) context->received_packets * 100.0 /
           (double) context->sent_packets);
    fflush(stdout);

    return 0;
}

static int
periodically_update_status(Context * const context)
{
    unsigned long long now = get_nanoseconds();

    if (now - context->last_status_update < UPDATE_STATUS_PERIOD) {
        return 1;
    }
    update_status(context);
    context->last_status_update = now;

    return 0;
}

static int
empty_receive_queue(Context * const context, int timeout)
{
    while (receive(context, timeout) > 0)
        ;
    periodically_update_status(context);

    return 0;
}

static int
throttled_receive(Context * const context)
{
    unsigned long long       now = get_nanoseconds(), now2;
    int                      remaining_ms;

    /* elapsed ns since start */
    const unsigned long long elapsed = now - context->startup_date;

    /* our target rate in nanoseconds per packet */
    const unsigned long long npp = NANOS_PER_SECOND / context->pps;

    /*
     * the amount of time we would have expected to pass if we were 
     * actually sending at the target rate
     */
    const unsigned long long target_elapsed_for_packets =
      context->sent_packets * npp;

    /* the max number of packets we should have seen since start */
    const unsigned long long max_packets =
      (context->pps * elapsed) / NANOS_PER_SECOND;

    if (context->sending == 1 && context->sent_packets <= max_packets) {
        empty_receive_queue(context, 0);
    }

    unsigned long long diff;
    int packets;
    unsigned long long remaining_time_ns =
      (elapsed >= target_elapsed_for_packets) ? 0 :
      (target_elapsed_for_packets - elapsed);

    if (context->sending == 0) {
        /*
	 * don't wait forever because packets may not actually return to us,
         * especially if we're using the -R flag with IPs that we don't own
         */
        remaining_time_ns = 2 * NANOS_PER_SECOND;
    }

    do {
        remaining_ms = (int) (remaining_time_ns / 1000000ULL);
	if (remaining_ms <= 0) {
	  break;
	}

        packets = receive(context, remaining_ms);
	if (packets > 0) {
	    periodically_update_status(context);
	}

        now2 = get_nanoseconds();

	diff = (now2 - now);

	remaining_time_ns = (remaining_time_ns > diff) ?
	  (remaining_time_ns - diff) : 0;

        now = now2;
    } while (remaining_time_ns > 0);

    return 0;
}

int
main(int argc, char *argv[])
{
    char             name[100U] = ".";
    Context          context;
    const char      *host;
    const char      *port = "domain";
    unsigned long    pps        = ULONG_MAX;
    unsigned long    send_count = ULONG_MAX;
    uint16_t         type;
    _Bool            fuzz = 0;
    int              ch;
    char             *endptr;
    int              do_receive = 1;
    in_addr_t        lowaddr = 0, highaddr = 0;

    while ((ch = getopt(argc, argv, "c:d:Fhnp:r:R:")) != -1) {
      switch (ch) {
      case 'c':
        if ((optarg == NULL) || (*optarg == '\0')) {
	  fprintf(stderr, "-c flag requires an integer query count\n");
	  exit(1);
	}
	send_count = strtoul(optarg, &endptr, 10);
	if (*endptr != '\0') {
	  fprintf(stderr, "invalid count for -c flag\n");
	  exit(1);
	}
	break;

      case 'd':
        if ((optarg == NULL) || (*optarg == '\0')) {
	  fprintf(stderr, "-d flag requires a domain name\n");
	  exit(1);
	}
	if (optarg[0] != '.') {
	  fprintf(stderr, "the domain name must include the leading dot\n");
	  exit(1);
	}
	domain_name = optarg;
	break;


      case 'F':
	fuzz = 1;
	break;

      case 'h':
	usage();
	break;

      case 'n':
	do_receive = 0;
	break;

      case 'p':
        if ((optarg == NULL) || (*optarg == '\0')) {
	  fprintf(stderr, "-p flag requires a port number or name\n");
	  exit(1);
	}
	port = optarg;
	break;

      case 'r':
        if ((optarg == NULL) || (*optarg == '\0')) {
	  fprintf(stderr,
		  "-r flag requires an integer rate in packets per second\n");
	  exit(1);
	}
	pps = strtoul(optarg, &endptr, 10);
	if ((*endptr != '\0') || (pps < 1)) {
	  fprintf(stderr, "invalid rate for -r flag\n");
	  exit(1);
	}
	break;

      case 'R':
        if ((optarg == NULL) || (*optarg == '\0')) {
	  fprintf(stderr, "-R flag requires a range\n");
	  exit(1);
	} else {
	  const char *delim = ":";
	  char *pair = strdup(optarg);
	  char *high = NULL;
	  char *low = strtok(pair, delim);
	  if (low != NULL) {
	    high = strtok(NULL, delim);
	  }
	  if ((low == NULL) || (high == NULL)) {
	    fprintf(stderr, "Invalid range for -R flag\n");
	    exit(1);
	  }
	  lowaddr = inet_addr(low);
	  highaddr = inet_addr(high);
	  if ((lowaddr == INADDR_NONE) || (highaddr == INADDR_NONE)) {
	    fprintf(stderr,
		    "Invalid range for -R flag (only IPv4 is supported)\n");
	    exit(1);
	  }
	}
	break;

      default:
	usage();
      }
    }
    argc -= optind;
    argv += optind;

    if (argc < 1) {
        usage();
    }
    host = argv[0];

    init_context(&context, host, port, lowaddr, highaddr, fuzz);
    context.pps = pps;
    srand(0U);
    assert(send_count > 0UL);
    do {
        if (rand() > REPEATED_NAME_PROBABILITY) {
            get_random_name(name, sizeof name);
        }
        type = get_random_type();
        blast(&context, name, type);
	/* 
	 * we need to do throttled_receive there even if do_receive is zero
	 * because it is how we control the rate
	 */
	throttled_receive(&context); 
    } while (--send_count > 0UL);
    update_status(&context);

    context.sending = 0;
    if (do_receive) {
      throttled_receive(&context);
    }
    clear_context(&context);
    update_status(&context);
    putchar('\n');

    return 0;
}
