package proc

import (
	"fmt"
	"log"
	"os"
	"strings"

	"github.com/prometheus/procfs"
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

func (proc *Proc) Snapshot() (snapshot *Snapshot, err error) {
	fs, err := procfs.NewDefaultFS()
	if err != nil {
		return
	}
	p, err := fs.Proc(proc.pid)
	if err != nil {
		return
	}
	procMaps, err := p.ProcMaps()
	if err != nil {
		return
	}
	snapshot = &Snapshot{}
	for _, procMap := range procMaps {
		if procMap.Perms.Read && strings.HasPrefix(procMap.Pathname, "/") {
			piece, err := newMemoryPiece(proc, procMap)
			if err != nil {
				return nil, err
			}
			snapshot.Texts = append(snapshot.Texts, piece)
		} else if procMap.Perms.Read && procMap.Pathname == "" && procMap.StartAddr >= 0xc000000000 && procMap.StartAddr < 0xd000000000 {
			piece, err := newMemoryPiece(proc, procMap)
			if err != nil {
				return nil, err
			}
			snapshot.Heaps = append(snapshot.Heaps, piece)
		} else if procMap.Perms.Read && procMap.Pathname == "" && len(snapshot.Heaps) == 0 && len(snapshot.Texts) > 0 {
			piece, err := newMemoryPiece(proc, procMap)
			if err != nil {
				return nil, err
			}
			snapshot.Others = append(snapshot.Others, piece)
		}
	}
	return
}

func (proc *Proc) ReadMemory(start, size uint64) (data []byte, err error) {
	data = make([]byte, size)
	_, err = proc.memFile.ReadAt(data, int64(start))
	return
}
