package main

import (
	"encoding/binary"
	"errors"
	"fmt"
	"log"

	"github.com/jschwinger233/go-spy/elf"
	"github.com/jschwinger233/go-spy/proc"
)

type Allgs struct {
	Gs  []*Goroutine
	Len uint64
}

type Goroutine struct {
	Goid    uint64
	Status  uint32
	StackLo uint64
	StackHi uint64
}

func parseGoroutines(ei *elf.ELFInfo, snapshot *proc.Snapshot) (goroutines []*Goroutine, err error) {
	addrOfAllgs, err := searchAllgs(ei, snapshot)
	if err != nil {
		return
	}
	fmt.Printf("allgs: %#x\n", addrOfAllgs)
	return
}

func searchAllgs(ei *elf.ELFInfo, snapshot *proc.Snapshot) (allgs *Allgs, err error) {
	for _, piece := range append(snapshot.Texts, snapshot.Others...) {
		for addr := piece.Start; addr < piece.Start+piece.Size; addr += 8 {
			allgsPointer := &Pointer{
				addr:     addr,
				proto:    ei.AllgsProto,
				snapshot: snapshot,
			}
			if allgs, err = derefAllgs(allgsPointer, ei); err != nil {
				//fmt.Printf("derefAllgs failed: %v\n", err)
				continue
			}
			fmt.Printf("allgs found at %#x\n", addr)
			return
		}
	}
	return allgs, errors.New("allgs not found")
}

type Pointer struct {
	addr     uint64
	proto    *elf.Proto
	snapshot *proc.Snapshot
}

func (p *Pointer) Field(name string) Bytes {
	field, found := p.proto.GetField(name)
	if !found {
		// Should never happen, so panic.
		log.Fatalf("field %s not found", name)
	}
	return p.snapshot.MustX(p.addr+field.Offset, field.Size)
}

func (p *Pointer) Index(i, size uint64) Bytes {
	return p.snapshot.MustX(p.addr+i*size, size)
}

type Bytes []byte

func (b Bytes) ToUint64() uint64 {
	return binary.LittleEndian.Uint64(b)
}

func (b Bytes) ToUint32() uint32 {
	return binary.LittleEndian.Uint32(b)
}

func derefAllgs(allgsPointer *Pointer, ei *elf.ELFInfo) (allgs *Allgs, err error) {
	allgs = &Allgs{}
	allgs.Len = allgsPointer.Field("len").ToUint64()
	if allgs.Len < 3 {
		return nil, fmt.Errorf("allgs.len (%d) < 3", allgs.Len)
	}
	array := allgsPointer.Field("array").ToUint64()
	if array == 0 {
		return nil, fmt.Errorf("allgs.array == 0")
	}
	arrayPointer := &Pointer{
		addr:     array,
		snapshot: allgsPointer.snapshot,
	}
	for i := uint64(0); i < allgs.Len; i++ {
		g := &Goroutine{}
		gPointer := &Pointer{
			addr:     arrayPointer.Index(i, 8).ToUint64(),
			proto:    ei.GProto,
			snapshot: allgsPointer.snapshot,
		}
		g.Goid = gPointer.Field("goid").ToUint64()
		if i == 0 && g.Goid != 1 {
			return nil, fmt.Errorf("allgs.array[0].goid (%d) != 1", g.Goid)
		}
		g.Status = gPointer.Field("atomicstatus").ToUint32()
		if g.Status < 1 || g.Status > 9 {
			return nil, fmt.Errorf("allgs.array[%d].atomicstatus (%d) < 1 || > 9", i, g.Status)
		}
		g.StackLo = gPointer.Field("stack.lo").ToUint64()
		g.StackHi = gPointer.Field("stack.hi").ToUint64()
		if g.Status != 6 && (g.StackLo == 0 || g.StackHi == 0) {
			return nil, fmt.Errorf("allgs.array[%d].stack.lo (%#x) or stack.hi (%#x) == 0", i, g.StackLo, g.StackHi)
		}
		if g.StackHi < g.StackLo || (g.StackHi-g.StackLo)%1024 != 0 {
			return nil, fmt.Errorf("(allgs.array[%d].stack.hi (%#x) - stack.lo (%#x)) % 1024 != 0", i, g.StackHi, g.StackLo)
		}
		allgs.Gs = append(allgs.Gs, g)
	}
	return allgs, nil
}
