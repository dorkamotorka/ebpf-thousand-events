package main

//go:generate go run github.com/cilium/ebpf/cmd/bpf2go -target amd64 trace trace.c

import (
	"bytes"
	"encoding/binary"
	"fmt"
	"log"
	"os"
	"os/signal"
	"syscall"
	"time"

	"github.com/cilium/ebpf/rlimit"
	"github.com/cilium/ebpf/link"
	"github.com/cilium/ebpf/ringbuf"
)

// Define the event structure matching the eBPF struct
type event struct {
	PID  uint32
}

func main() {
	// Remove resource limits for kernels <5.11.
	if err := rlimit.RemoveMemlock(); err != nil {
		log.Fatal("Removing memlock:", err)
	}

	// Load the compiled eBPF ELF and load it into the kernel.
	var obj traceObjects
	if err := loadTraceObjects(&obj, nil); err != nil {
		log.Fatal("Loading eBPF objects:", err)
	}
	defer obj.Close()

	// Attach kprobe to the getpid syscall
	kp, err := link.Kprobe("__x64_sys_getpid", obj.TraceGetpid, nil)
	if err != nil {
		log.Fatalf("Failed to attach kprobe: %v", err)
	}
	defer kp.Close()

	// Open ring buffer to read events
	rb, err := ringbuf.NewReader(obj.Events)
	if err != nil {
		log.Fatalf("Failed to open ring buffer: %v", err)
	}
	defer rb.Close()

	// Handle Ctrl+C to clean up
	stop := make(chan os.Signal, 1)
	signal.Notify(stop, os.Interrupt, syscall.SIGTERM)

	fmt.Println("Listening for getpid() syscalls... Press Ctrl+C to exit.")

	go func() {
		for {
			var key uint32 = 0
			var available uint64
			if err := obj.CountMap.Lookup(&key, &available); err != nil {
                        	log.Fatalf("Failed to lookup map: %v", err)
                	}

			fmt.Print("\033[H\033[J")
			fmt.Printf("Ring Buffer has %d bytes of data available to be consumed.", available)
			time.Sleep(100 * time.Millisecond)
		}
	}()

	go func() {
		var e event
		for {
			record, err := rb.Read()
			if err != nil {
				if err == ringbuf.ErrClosed {
					return
				}
				//log.Printf("Error reading ring buffer: %v", err)
				continue
			}

			// Parse binary data into event struct
			if err := binary.Read(bytes.NewBuffer(record.RawSample), binary.LittleEndian, &e); err != nil {
				log.Printf("Failed to parse event: %v", err)
				continue
			}

			//fmt.Printf("PID: %d\n", e.PID)
		}
	}()

	<-stop
	fmt.Println("\nExiting...")
}
