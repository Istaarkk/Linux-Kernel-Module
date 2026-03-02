#include <stdio.h>
#include <stdlib.h>
#include <unistd.h>
#include <signal.h>
#include <bpf/libbpf.h>
#include <bpf/bpf.h>

static volatile int running = 1;

struct event {
    unsigned int pid;
    char comm[16];
    char fname[256];
};

static void sig_handler(int sig) { (void)sig; running = 0; }

static int handle_event(void *ctx, void *data, size_t size)
{
    struct event *e = data;
    printf("[pid=%-6u comm=%-16s] %s\n", e->pid, e->comm, e->fname);
    return 0;
}

int main(void)
{
    struct bpf_object *obj;
    struct bpf_program *prog;
    struct bpf_link *link;
    struct ring_buffer *rb;
    int map_fd, err;

    obj = bpf_object__open_file("hook.bpf.o", NULL);
    if (libbpf_get_error(obj)) { fprintf(stderr, "Erreur open\n"); return 1; }

    err = bpf_object__load(obj);
    if (err) { fprintf(stderr, "Erreur load\n"); return 1; }

    prog = bpf_object__find_program_by_name(obj, "hook_openat");
    if (!prog) { fprintf(stderr, "Erreur prog\n"); return 1; }

    link = bpf_program__attach(prog);
    if (libbpf_get_error(link)) { fprintf(stderr, "Erreur attach\n"); return 1; }

    map_fd = bpf_object__find_map_fd_by_name(obj, "events");
    if (map_fd < 0) { fprintf(stderr, "Erreur map\n"); return 1; }

    rb = ring_buffer__new(map_fd, handle_event, NULL, NULL);
    if (!rb) { fprintf(stderr, "Erreur ring_buffer\n"); return 1; }

    signal(SIGINT, sig_handler);
    signal(SIGTERM, sig_handler);

    printf("Starting\n");

    while (running) {
        err = ring_buffer__poll(rb, 100);
        if (err < 0 && running) {
            fprintf(stderr, "Erreur poll: %d\n", err);
            break;
        }
    }

    ring_buffer__free(rb);
    bpf_link__destroy(link);
    bpf_object__close(obj);
    return 0;
}
