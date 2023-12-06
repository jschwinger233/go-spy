package proc

import (
	"github.com/prometheus/procfs"
)

type MemoryPiece struct {
	Start uint64
	Size  uint64
	Data  []byte
}

func newMemoryPiece(proc *Proc, procMap *procfs.ProcMap) (piece *MemoryPiece, err error) {
	piece = &MemoryPiece{}
	piece.Start = uint64(procMap.StartAddr)
	piece.Size = uint64(procMap.EndAddr) - uint64(procMap.StartAddr)
	piece.Data, err = proc.ReadMemory(piece.Start, piece.Size)
	return
}

type Snapshot struct {
	Texts, Others, Heaps []*MemoryPiece
}

func (s *Snapshot) InitAddr() uint64 {
	return s.Texts[0].Start
}

func (s *Snapshot) X(addr, size uint64) (data []byte) {
	data = make([]byte, size)
	for _, piece := range append(s.Texts, append(s.Others, s.Heaps...)...) {
		if addr >= piece.Start && addr < piece.Start+piece.Size {
			data = piece.Data[addr-piece.Start : addr-piece.Start+size]
			break
		}
	}
	return
}
