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

	println("parsing elf")
	elfInfo, err := elf.GetFromPid(pid).Parse()
	if err != nil {
		log.Fatalf("Error parsing ELF: %v", err)
	}

	println("taking snapshot")
	snapshot, err := proc.Get(pid).Snapshot()
	if err != nil {
		log.Fatalf("Error taking snapshot: %v", err)
	}

	println("parsing goroutines")
	goroutines, err := parseGoroutines(elfInfo, snapshot)
	if err != nil {
		log.Fatalf("Error parsing snapshot: %v", err)
	}

	initAddr := snapshot.InitAddr()
	for _, goroutine := range goroutines {
		fmt.Printf("-- goid %d\n", goroutine.Goid)
		fmt.Printf("  %s\n", elfInfo.LookupSymbol(goroutine.Pc-initAddr).Name)
		for frame := goroutine.Frame(); frame.Bp != 0; frame = frame.Next(snapshot) {
			fmt.Printf("  %s\n", elfInfo.LookupSymbol(frame.Pc(snapshot)-initAddr).Name)
		}
	}
}
