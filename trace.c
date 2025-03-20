//go:build ignore
#include "vmlinux.h"
#include <bpf/bpf_helpers.h>
#include <bpf/bpf_tracing.h>

struct event_t {
    u32 pid;
};

// Define a ring buffer to send events to user space
struct {
    __uint(type, BPF_MAP_TYPE_RINGBUF);
    __uint(max_entries, 1 << 12); // 4KB buffer
} events SEC(".maps");

struct {
    __uint(type, BPF_MAP_TYPE_ARRAY);
    __type(key, __u32);
    __type(value, __u64);
    __uint(max_entries, 1);
} count_map SEC(".maps");

SEC("kprobe/__x64_sys_getpid")
int trace_getpid(struct pt_regs *ctx) {
    struct event_t *event;
    
    // Reserve space in the ring buffer
    event = bpf_ringbuf_reserve(&events, sizeof(struct event_t), 0);
    if (!event)
        return 0;

    // Populate event data
    event->pid = bpf_get_current_pid_tgid() >> 32;

    // Submit event to ring buffer
    bpf_ringbuf_submit(event, 0);

    __u32 key = 0;
    // bpf_ringbuf_query with BPF_RB_AVAIL_DATA flag - Retrieves the number of bytes in the ring buffer that have been written but not yet consumed
    __u64 available = bpf_ringbuf_query(&events, BPF_RB_AVAIL_DATA);
    int result = bpf_map_update_elem(&count_map, &key, &available, BPF_ANY);
    if (result != 0) {
        bpf_printk("Failed to update Map with new element\n");
    }

    return 0;
}

char LICENSE[] SEC("license") = "GPL";
