#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>
#include <pthread.h>
#include <sys/socket.h>
#include <netinet/in.h>
#include <netinet/ip.h>
#include <netinet/tcp.h>
#include <arpa/inet.h>
#include <netdb.h>
#include <errno.h>
#include <getopt.h>

#define MAX_THREADS 100
#define DEFAULT_TIMEOUT 1000  // ms
#define MAX_PORT 65535

typedef struct {
    char ip[16];
    int start_port;
    int end_port;
    int timeout;
    int ghost_mode;
    int udp_scan;
    char* output_file;
    int thread_count;
} scan_config;

typedef struct {
    int port;
    int is_open;
    char service[32];
    char status[16];
} port_result;

typedef struct {
    char* target_ip;
    int start_port;
    int end_port;
    int timeout;
    int ghost_mode;
    port_result* results;
    pthread_mutex_t* mutex;
} thread_args;

// Nouvelle fonction pour convertir une URL en IP
char* url_to_ip(const char* url, char* ip_buffer, size_t buffer_size) {
    struct hostent *he;
    struct in_addr **addr_list;
    
    const char* clean_url = url;
    if (strncmp(url, "http://", 7) == 0) {
        clean_url = url + 7;
    } else if (strncmp(url, "https://", 8) == 0) {
        clean_url = url + 8;
    }
    
    char domain[256];
    strncpy(domain, clean_url, sizeof(domain) - 1);
    domain[sizeof(domain) - 1] = '\0';
    char* slash = strchr(domain, '/');
    if (slash) *slash = '\0';
    
    if ((he = gethostbyname(domain)) == NULL) {
        return NULL;
    }
    
    addr_list = (struct in_addr **)he->h_addr_list;
    if (addr_list[0] == NULL) {
        return NULL;
    }
    
    strncpy(ip_buffer, inet_ntoa(*addr_list[0]), buffer_size - 1);
    ip_buffer[buffer_size - 1] = '\0';
    
    return ip_buffer;
}

void identify_service(int port, char* service) {
    switch(port) {
        case 21: strcpy(service, "FTP"); break;
        case 22: strcpy(service, "SSH"); break;
        case 23: strcpy(service, "Telnet"); break;
        case 25: strcpy(service, "SMTP"); break;
        case 53: strcpy(service, "DNS"); break;
        case 80: strcpy(service, "HTTP"); break;
        case 443: strcpy(service, "HTTPS"); break;
        default: strcpy(service, "Unknown");
    }
}

int scan_tcp_port(const char* ip, int port, int timeout, int ghost_mode) {
    struct sockaddr_in addr;
    int sockfd;
    
    sockfd = socket(AF_INET, SOCK_STREAM, 0);
    if (sockfd < 0) return -1;
    
    struct timeval tv;
    tv.tv_sec = timeout / 1000;
    tv.tv_usec = (timeout % 1000) * 1000;
    setsockopt(sockfd, SOL_SOCKET, SO_RCVTIMEO, &tv, sizeof(tv));
    setsockopt(sockfd, SOL_SOCKET, SO_SNDTIMEO, &tv, sizeof(tv));
    
    addr.sin_family = AF_INET;
    addr.sin_port = htons(port);
    addr.sin_addr.s_addr = inet_addr(ip);
    
    if (ghost_mode) {
        usleep(rand() % 500000);
    }
    
    if (connect(sockfd, (struct sockaddr*)&addr, sizeof(addr)) == 0) {
        close(sockfd);
        return 1;
    }
    
    close(sockfd);
    return 0;
}

void* scan_thread(void* arg) {
    thread_args* args = (thread_args*)arg;
    int i;
    
    for (i = args->start_port; i <= args->end_port; i++) {
        int result = scan_tcp_port(args->target_ip, i, args->timeout, args->ghost_mode);
        
        pthread_mutex_lock(args->mutex);
        args->results[i].port = i;
        args->results[i].is_open = result;
        if (result == 1) {
            strcpy(args->results[i].status, "open");
            identify_service(i, args->results[i].service);
        } else {
            strcpy(args->results[i].status, "closed/filtered");
            strcpy(args->results[i].service, "-");
        }
        pthread_mutex_unlock(args->mutex);
    }
    
    return NULL;
}

void run_scan(scan_config* config) {
    pthread_t threads[MAX_THREADS];
    thread_args thread_configs[MAX_THREADS];
    pthread_mutex_t mutex = PTHREAD_MUTEX_INITIALIZER;
    port_result* results;
    int ports_per_thread;
    int i;
    
    results = calloc(config->end_port + 1, sizeof(port_result));
    if (!results) {
        printf("Erreur d'allocation mémoire\n");
        return;
    }
    
    ports_per_thread = (config->end_port - config->start_port + 1) / config->thread_count;
    
    for (i = 0; i < config->thread_count; i++) {
        thread_configs[i].target_ip = config->ip;
        thread_configs[i].start_port = config->start_port + (i * ports_per_thread);
        thread_configs[i].end_port = (i == config->thread_count - 1) ? 
                                   config->end_port : 
                                   config->start_port + ((i + 1) * ports_per_thread - 1);
        thread_configs[i].timeout = config->timeout;
        thread_configs[i].ghost_mode = config->ghost_mode;
        thread_configs[i].results = results;
        thread_configs[i].mutex = &mutex;
        
        if (pthread_create(&threads[i], NULL, scan_thread, &thread_configs[i]) != 0) {
            printf("Erreur lors de la création du thread %d\n", i);
            return;
        }
    }
    
    for (i = 0; i < config->thread_count; i++) {
        pthread_join(threads[i], NULL);
    }
    
    printf("\nRésultats du scan pour %s:\n", config->ip);
    printf("PORT\tSTATUS\t\tSERVICE\n");
    printf("------------------------------------\n");
    
    for (i = config->start_port; i <= config->end_port; i++) {
        if (results[i].is_open) {
            printf("%d\t%s\t\t%s\n", results[i].port, results[i].status, results[i].service);
        }
    }
    
    if (config->output_file) {
        FILE* f = fopen(config->output_file, "w");
        if (f) {
            fprintf(f, "PORT\tSTATUS\t\tSERVICE\n");
            fprintf(f, "------------------------------------\n");
            for (i = config->start_port; i <= config->end_port; i++) {
                if (results[i].is_open) {
                    fprintf(f, "%d\t%s\t\t%s\n", results[i].port, results[i].status, results[i].service);
                }
            }
            fclose(f);
        }
    }
    
    free(results);
}

void print_usage() {
    printf("Usage: rmap [options]\n");
    printf("Options:\n");
    printf("  -t <IP>           IP cible\n");
    printf("  -u <URL>          URL cible (ex: example.com)\n");
    printf("  -p <start-end>    Plage de ports (ex: 20-80)\n");
    printf("  --ghost           Mode furtif\n");
    printf("  --timeout <ms>    Timeout en millisecondes\n");
    printf("  --udp             Scan UDP (non implémenté)\n");
    printf("  -o <fichier>      Fichier de sortie\n");
    printf("  -h                Aide\n");
}

int main(int argc, char* argv[]) {
    scan_config config = {
        .start_port = 1,
        .end_port = 1024,
        .timeout = DEFAULT_TIMEOUT,
        .ghost_mode = 0,
        .udp_scan = 0,
        .output_file = NULL,
        .thread_count = 10
    };
    
    char url_buffer[256] = {0};
    int opt;
    
    static struct option long_options[] = {
        {"ghost", no_argument, 0, 'g'},
        {"timeout", required_argument, 0, 'm'},
        {"udp", no_argument, 0, 'u'},
        {0, 0, 0, 0}
    };
    
    while ((opt = getopt_long(argc, argv, "t:u:p:o:hm:g", long_options, NULL)) != -1) {
        switch (opt) {
            case 't':
                strncpy(config.ip, optarg, sizeof(config.ip) - 1);
                break;
            case 'u': {
                if (url_to_ip(optarg, config.ip, sizeof(config.ip)) == NULL) {
                    printf("Erreur: Impossible de résoudre l'URL %s\n", optarg);
                    return 1;
                }
                strncpy(url_buffer, optarg, sizeof(url_buffer) - 1);
                break;
            }
            case 'p': {
                char* hyphen = strchr(optarg, '-');
                if (hyphen) {
                    *hyphen = '\0';
                    config.start_port = atoi(optarg);
                    config.end_port = atoi(hyphen + 1);
                }
                break;
            }
            case 'g':
                config.ghost_mode = 1;
                break;
            case 'm':
                config.timeout = atoi(optarg);
                break;
            case 'o':
                config.output_file = optarg;
                break;
            case 'h':
                print_usage();
                return 0;
            default:
                print_usage();
                return 1;
        }
    }
    
    if (strlen(config.ip) == 0) {
        printf("Erreur: IP ou URL cible requise (-t ou -u)\n");
        return 1;
    }
    
    if (getuid() != 0) {
        printf("Attention: Ce programme nécessite les droits root\n");
        return 1;
    }
    
    printf("Démarrage du scan sur %s (%s) (ports %d-%d)\n", 
           url_buffer[0] ? url_buffer : config.ip,
           config.ip,
           config.start_port, config.end_port);
    if (config.ghost_mode) printf("Mode ghost activé\n");
    
    run_scan(&config);
    
    return 0;
}
