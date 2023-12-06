package main

import (
	"encoding/binary"
	"errors"
	"fmt"
	"log"

	"github.com/jschwinger233/go-spy/elf"
	"github.com/jschwinger233/go-spy/proc"
)

type GoroutineStatus = uint32

const (
	Runnable GoroutineStatus = iota + 1
	Running
	Syscall
	Waiting
	Moribund
	Dead
	Enqueue
	Copystack
	Preempt
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
	Pc, Bp  uint64
}

func (g *Goroutine) Validate(idx uint64) (err error) {
	if idx == 0 && g.Goid != 1 {
		return fmt.Errorf("goid (%d) != 1", g.Goid)
	}
	if g.Status < Runnable || g.Status > Preempt {
		return fmt.Errorf("status (%d) < 1 || > 9", g.Status)
	}
	if g.Status != Dead && (g.StackLo == 0 || g.StackHi == 0) {
		return fmt.Errorf("allgs.array[%d].stack.lo (%#x) or stack.hi (%#x) == 0", idx, g.StackLo, g.StackHi)
	}
	if g.StackHi < g.StackLo || (g.StackHi-g.StackLo)%1024 != 0 {
		return fmt.Errorf("(allgs.array[%d].stack.hi (%#x) - stack.lo (%#x)) % 1024 != 0", idx, g.StackHi, g.StackLo)
	}
	return
}
func (g *Goroutine) StatusName() string {
	switch g.Status {
	case Runnable:
		return "runnable"
	case Running:
		return "running"
	case Syscall:
		return "syscall"
	case Waiting:
		return "waiting"
	case Moribund:
		return "moribund"
	case Dead:
		return "dead"
	case Enqueue:
		return "enqueue"
	case Copystack:
		return "copystack"
	case Preempt:
		return "preempty"
	}
	return "unknown"
}

func (g *Goroutine) Frame() *Frame {
	return &Frame{g.Bp}
}

type Frame struct {
	Bp uint64
}

func (f *Frame) Next(snapshot *proc.Snapshot) *Frame {
	return &Frame{Bytes(snapshot.X(f.Bp, 8)).ToUint64()}
}

func (f *Frame) Pc(snapshot *proc.Snapshot) uint64 {
	return Bytes(snapshot.X(f.Bp+8, 8)).ToUint64()
}

func parseGoroutines(ei *elf.ELFInfo, snapshot *proc.Snapshot) (goroutines []*Goroutine, err error) {
	allgs, err := searchAllgs(ei, snapshot)
	if err != nil {
		return
	}
	return allgs.Gs, nil
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
	return p.snapshot.X(p.addr+field.Offset, field.Size)
}

func (p *Pointer) Index(i, size uint64) Bytes {
	return p.snapshot.X(p.addr+i*size, size)
}

type Bytes []byte

func (b Bytes) ToUint64() uint64 {
	return binary.LittleEndian.Uint64(b)
}

func (b Bytes) ToUint32() uint32 {
	return binary.LittleEndian.Uint32(b)
}

func derefAllgs(allgsPointer *Pointer, ei *elf.ELFInfo) (allgs *Allgs, err error) {
	allgs = &Allgs{
		Len: allgsPointer.Field("len").ToUint64(),
	}
	if allgs.Len < 3 {
		return nil, fmt.Errorf("allgs.len (%d) < 3", allgs.Len)
	}
	arrayPointer := &Pointer{
		addr:     allgsPointer.Field("array").ToUint64(),
		snapshot: allgsPointer.snapshot,
	}
	if arrayPointer.addr == 0 {
		return nil, fmt.Errorf("allgs.array == 0")
	}
	for i := uint64(0); i < allgs.Len; i++ {
		gPointer := &Pointer{
			addr:     arrayPointer.Index(i, 8).ToUint64(),
			proto:    ei.GProto,
			snapshot: allgsPointer.snapshot,
		}
		g := &Goroutine{
			Goid:    gPointer.Field("goid").ToUint64(),
			Status:  gPointer.Field("atomicstatus").ToUint32(),
			StackLo: gPointer.Field("stack.lo").ToUint64(),
			StackHi: gPointer.Field("stack.hi").ToUint64(),
			Pc:      gPointer.Field("sched.pc").ToUint64(),
			Bp:      gPointer.Field("sched.bp").ToUint64(),
		}
		if err = g.Validate(i); err != nil {
			return
		}
		allgs.Gs = append(allgs.Gs, g)
	}
	return allgs, nil
}
