package proc

import (
	"fmt"
	"log"
	"os"
)

type Proc struct {
	pid     int
	memFile *os.File
}

func Get(pid int) *Proc {
	memFile, err := os.Open(fmt.Sprintf("/proc/%d/mem", pid))
	if err != nil {
		log.Fatalf("Failed to open /proc/%d/mem: %v", pid, err)
	}
	return &Proc{
		pid:     pid,
		memFile: memFile,
	}
}
