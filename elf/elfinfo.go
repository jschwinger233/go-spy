package elf

import (
	"debug/elf"
	"fmt"
	"os"
	"slices"
)

type Symbol struct {
	Offset uint64
	Name   string
}

type Symbols []Symbol // sorted

type G struct {
	Size    uint64
	Offsets map[string]uint64
}

func (g *G) FieldOffset(name string) uint64 {
	return g.Offsets[name]
}

type ELFInfo struct {
	GoVersion string
	Symbols
	GProto, AllgsProto *Proto

	UnrealRuntimeGoexitOffset uint64
}

func (e ELFInfo) LookupSymbol(offset uint64) Symbol {
	idx, _ := slices.BinarySearchFunc(e.Symbols, offset, func(x Symbol, offset uint64) int {
		if x.Offset > offset {
			return 1
		} else if x.Offset < offset {
			return -1
		}
		return 0
	})
	if idx == len(e.Symbols) {
		return e.Symbols[idx-1]
	}
	if e.Symbols[idx].Offset == offset {
		return e.Symbols[idx]
	}
	if idx == 0 {
		return e.Symbols[0]
	}
	return e.Symbols[idx-1]

}

func (e *ELF) Parse() (elfInfo *ELFInfo, err error) {
	metadata, err := recoverMetadata(e.filename)
	if err != nil {
		return
	}
	elfInfo = &ELFInfo{GoVersion: metadata.Version}
	f, err := os.Open(e.filename)
	if err != nil {
		return
	}
	defer f.Close()
	elfFile, err := elf.NewFile(f)
	if err != nil {
		return
	}
	textSection := elfFile.Section(".text")
	for _, f := range metadata.Functions {
		if f.FullName == "runtime.goexit" {
			elfInfo.UnrealRuntimeGoexitOffset = f.Start - textSection.Addr + textSection.Offset
		}
		elfInfo.Symbols = append(elfInfo.Symbols,
			Symbol{
				Offset: f.Start - textSection.Addr + textSection.Offset,
				Name:   f.FullName,
			})
	}
	slices.SortFunc(elfInfo.Symbols,
		func(a, b Symbol) int {
			if a.Offset < b.Offset {
				return -1
			} else if a.Offset > b.Offset {
				return 1
			}
			return 0
		})
	elfInfo.GProto = &Proto{
		Fields: map[string]*Field{
			"goid":         &Field{152, 8},
			"atomicstatus": &Field{144, 4},
			"stack.lo":     &Field{0, 8},
			"stack.hi":     &Field{8, 8},
			"sched.pc":     &Field{56 + 8, 8},
			"sched.bp":     &Field{56 + 48, 8},
		},
	}
	elfInfo.AllgsProto = &Proto{
		Fields: map[string]*Field{
			"array": &Field{0, 8},
			"len":   &Field{8, 8},
		},
	}
	return
}

func (e *ELFInfo) AdjustOffset(offset uint64) {
	for idx, symbol := range e.Symbols {
		e.Symbols[idx].Offset = symbol.Offset + offset
		if symbol.Name == "main.main" {
			fmt.Printf("new main.main offset: %x\n", e.Symbols[idx].Offset)
		}
		if symbol.Name == "runtime.goexit" {
			fmt.Printf("new runtime.goexit offset: %x\n", e.Symbols[idx].Offset)
		}
	}
}

type Proto struct {
	Fields map[string]*Field
}

type Field struct {
	Offset uint64
	Size   uint64
}

func (p *Proto) GetField(name string) (*Field, bool) {
	field, ok := p.Fields[name]
	return field, ok
}
