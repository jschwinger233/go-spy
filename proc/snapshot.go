package proc

import (
	"strings"

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
		if procMap.Perms.Read && strings.HasPrefix(procMap.Pathname, "/") && len(snapshot.Others) == 0 {
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
		} else if procMap.Perms.Read && len(snapshot.Texts) > 0 {
			if len(snapshot.Others) > 0 {
				if lastOther := snapshot.Others[len(snapshot.Others)-1]; lastOther.Start+lastOther.Size != uint64(procMap.StartAddr) {
					continue
				}
			} else {
				if lastText := snapshot.Texts[len(snapshot.Texts)-1]; lastText.Start+lastText.Size != uint64(procMap.StartAddr) {
					continue
				}
			}
			piece, err := newMemoryPiece(proc, procMap)
			if err != nil {
				return nil, err
			}
			snapshot.Others = append(snapshot.Others, piece)
		}
	}

	return
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
