package main

import (
	"fmt"
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

	fmt.Printf("Parsing elf\n")
	elfInfo, err := elf.GetFromPid(pid).Parse()
	if err != nil {
		log.Fatalf("Error parsing ELF: %v", err)
	}

	fmt.Printf("Taking snapshot\n")
	snapshot, err := proc.Get(pid).Snapshot()
	if err != nil {
		log.Fatalf("Error taking snapshot: %v", err)
	}

	fmt.Printf("Parsing goroutines\n")
	goroutines, err := parseGoroutines(elfInfo, snapshot)
	if err != nil {
		log.Fatalf("Error parsing snapshot: %v", err)
	}

	initAddr := snapshot.InitAddr()
	for _, goroutine := range goroutines {
		if goroutine.Status == Dead {
			continue
		}
		fmt.Printf("-- Goroutine %d: %s\n", goroutine.Goid, goroutine.StatusName())
		printSymbol(goroutine.Pc, initAddr, elfInfo)
		for frame := goroutine.Frame(); frame.Bp != 0; frame = frame.Next(snapshot) {
			printSymbol(frame.Pc(snapshot), initAddr, elfInfo)
		}
	}
}

func printSymbol(pc, initAddr uint64, elfInfo *elf.ELFInfo) {
	symbol := elfInfo.LookupSymbol(pc - initAddr)
	fmt.Printf("  %s+%d\n", symbol.Name, pc-initAddr-symbol.Offset)
}
