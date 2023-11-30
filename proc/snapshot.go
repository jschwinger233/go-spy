package proc

import "github.com/prometheus/procfs"

type MemoryPiece struct {
	Start uint64
	Size  uint64
	Data  []byte
}

type Snapshot struct {
	Pieces []MemoryPiece
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
		if !procMap.Perms.Read || procMap.Pathname != "" {
			continue
		}
		piece := MemoryPiece{
			Start: uint64(procMap.StartAddr),
			Size:  uint64(procMap.EndAddr) - uint64(procMap.StartAddr),
		}
		piece.Data, err = proc.ReadMemory(piece.Start, piece.Size)
		if err != nil {
			return
		}
		snapshot.Pieces = append(snapshot.Pieces, piece)
	}
	return
}

func (proc *Proc) ReadMemory(start, size uint64) (data []byte, err error) {
	data = make([]byte, size)
	_, err = proc.memFile.ReadAt(data, int64(start))
	return
}
