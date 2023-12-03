package main

import (
	"log"
	"os"
	"strconv"

	"github.com/jschwinger233/go-spy/elf"
	"github.com/jschwinger233/go-spy/proc"
)

func help() string {
	return "Usage: go-spy <pid>"
}

func main() {
	if len(os.Args) != 2 {
		log.Fatal(help())
	}
	pid, err := strconv.Atoi(os.Args[1])
	if err != nil {
		log.Fatal(help())
	}

	elfInfo, err := elf.GetFromPid(pid).Parse()
	if err != nil {
		log.Fatalf("Error parsing ELF: %v", err)
	}

	snapshot, err := proc.Get(pid).Snapshot()
	if err != nil {
		log.Fatalf("Error taking snapshot: %v", err)
	}

	goroutines, err := parseGoroutines(elfInfo, snapshot)
	if err != nil {
		log.Fatalf("Error parsing snapshot: %v", err)
	}

	println(goroutines)
}
