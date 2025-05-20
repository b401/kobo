#include <netinet/in.h>
#define _GNU_SOURCE
#include <dlfcn.h>
#include <stdlib.h>
#include <netdb.h>
#include <string.h>
#include <stdint.h>
#include <stdio.h>
#include <unistd.h>
#include <sys/types.h>
#include <sys/socket.h>
#include <arpa/inet.h>

const char *DNS = "DNS";

// ignore getnameinfo() calls
int getnameinfo(const struct sockaddr *sa, socklen_t salen,
                char *host, socklen_t hostlen,
                char *serv, socklen_t servlen, int flags) {
    fprintf(stderr, "[kobo] getnameinfo() was called and is blocked.\n");
    return EAI_FAIL;
}

// ignore gethostbyname() calls
struct hostent *gethostbyname(const char *name) {
    fprintf(stderr, "[kobo] gethostbyname() was called with name: %s — blocked.\n", name);
    return NULL; // Return NULL to indicate failure (like a DNS failure)
}

int parse_dns_response(uint8_t *response, size_t len, char *ip_out) {
    if (len < 12) return 0;  // DNS header too short

    int answer_count = (response[6] << 8) | response[7];
    int i = 12;

    // Parse question section QNAME
    while (i < len) {
        if (response[i] == 0) {
            i++;
            break;
        } else if ((response[i] & 0xC0) == 0xC0) {
            // skip compression pointer
            // https://datatracker.ietf.org/doc/html/rfc1035#section-4.1.4
            i += 2;
            break;
        } else {
            uint8_t label_len = response[i];
            i += 1 + label_len;
            if (i > len) return 0;
        }
    }

    // Check space for QTYPE and QCLASS
    if (i + 4 > len) return 0;
    i += 4; // Skip QTYPE and QCLASS

    for (int a = 0; a < answer_count; a++) {
        // Skip answer name (could be compressed)
        if (i >= len) return 0;
        if ((response[i] & 0xC0) == 0xC0) {
            i += 2;
        } else {
            while (i < len) {
                if (response[i] == 0) {
                    i++;
                    break;
                } else if ((response[i] & 0xC0) == 0xC0) {
                    // skip compression pointer
                    // https://datatracker.ietf.org/doc/html/rfc1035#section-4.1.4
                    i += 2;
                    break;
                } else {
                    uint8_t label_len = response[i];
                    i += 1 + label_len;
                    if (i > len) return 0;
                }
            }
        }

        if (i + 10 > len) return 0;

        // https://datatracker.ietf.org/doc/html/rfc1035#section-3.2.2
        uint16_t type = (response[i] << 8) | response[i+1];
        // https://datatracker.ietf.org/doc/html/rfc1035#section-3.2.4
        uint16_t class = (response[i+2] << 8) | response[i+3];
        // https://datatracker.ietf.org/doc/html/rfc1035#section-4.1.3
        uint16_t rdlength = (response[i+8] << 8) | response[i+9];
        i += 10;

        // We only care about A records
        if (type == 1 && class == 1 && rdlength == 4 && i + 4 <= len) {  // A record
            inet_ntop(AF_INET, &response[i], ip_out, INET_ADDRSTRLEN);
            return 1;
        }

        i += rdlength;
        if (i > len) return 0;
    }

    return 0;
}

size_t dns_builder(uint8_t *buf, const char *hostname) {
    uint16_t id = htons(0x1339);
    uint16_t flags = htons(0x0100);  // Standard query
    uint16_t qdcount = htons(1);
    size_t offset = 0;

    memcpy(buf + offset, &id, 2); offset += 2;
    memcpy(buf + offset, &flags, 2); offset += 2;
    memcpy(buf + offset, &qdcount, 2); offset += 2;
    memset(buf + offset, 0, 6); offset += 6; // AN, NS, AR counts

    const char *p = hostname;
    while (*p) {
        const char *dot = strchr(p, '.');
        if (!dot) dot = p + strlen(p);

        uint8_t len = dot - p;
        buf[offset++] = len;
        memcpy(buf + offset, p, len);
        offset += len;
        p = (*dot == '.') ? dot + 1 : dot;
    }
    buf[offset++] = 0;

    uint16_t qtype = htons(1), qclass = htons(1);
    memcpy(buf + offset, &qtype, 2); offset += 2;
    memcpy(buf + offset, &qclass, 2); offset += 2;

    return offset;
}

ssize_t resolver(const char *dns_ip, const char *hostname, uint8_t *out_buf, size_t buf_size) {
    uint8_t query[512];
    size_t query_len = dns_builder(query, hostname);

    int sock = socket(AF_INET, SOCK_DGRAM, 0);
    if (sock < 0) {
        perror("socket");
        return -1;
    }

    struct sockaddr_in dest = {
        .sin_family = AF_INET,
        .sin_port = htons(53),
        .sin_addr = {0}
    };
    if (inet_pton(AF_INET, dns_ip, &dest.sin_addr) <= 0) {
        perror("inet_pton");
        close(sock);
        return -1;
    }

    if (connect(sock, (struct sockaddr*)&dest, sizeof(dest)) < 0) {
        perror("connect");
        close(sock);
        return -1;
    }

    ssize_t sent = send(sock, query, query_len, 0);
    if (sent < 0) {
        perror("send");
        close(sock);
        return -1;
    }

    ssize_t received = recv(sock, out_buf, buf_size, 0);
    close(sock);
    return received;
}

// overwrite getaddrinfo
int getaddrinfo(const char *name, const char *service, const struct addrinfo *req, struct addrinfo **pai) {
    static int (*real_getaddrinfo)(const char*, const char*, const struct addrinfo*, struct addrinfo**) = NULL;

    const char *dns_server = getenv(DNS);
    if (!dns_server) {
        fprintf(stderr, "[kobo] No DNS variable set, aborting..");
        exit(1);
    }

    uint8_t response[512];
    ssize_t resp_len = resolver(dns_server, name, response, sizeof(response));
    if (resp_len <= 0) return EAI_FAIL;


    char ip[INET_ADDRSTRLEN];
    if (!parse_dns_response(response, resp_len, ip)) return EAI_FAIL;

    if (req && req->ai_family != AF_UNSPEC && req->ai_family != AF_INET) {
        return EAI_FAMILY;
    }

    size_t total_size = sizeof(struct addrinfo) + sizeof(struct sockaddr_in);
    struct addrinfo *result = malloc(total_size);
    if (!result) return EAI_MEMORY;
    memset(result, 0, total_size);

    struct sockaddr_in *addr = (struct sockaddr_in*)(result + 1);
    addr->sin_family = AF_INET;
    addr->sin_port = 0;

    if (service) {
        struct servent *sv = getservbyname(service, req ? (req->ai_protocol == IPPROTO_TCP ? "tcp" : "udp") : NULL);
        addr->sin_port = sv ? sv->s_port : htons(atoi(service));
    }

    inet_pton(AF_INET, ip, &addr->sin_addr);

    result->ai_family = AF_INET;
    result->ai_socktype = req ? req->ai_socktype : 0;
    result->ai_protocol = req ? req->ai_protocol : 0;
    result->ai_addrlen = sizeof(*addr);
    result->ai_addr = (struct sockaddr*)addr;
    *pai = result;

    return 0;
}
