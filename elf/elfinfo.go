package elf

import (
	"debug/elf"
	"encoding/json"
	"os"
	"os/exec"
	"slices"
)

type Function struct {
	Address uint64 `json:"Start"`
	Name    string `json:"FullName"`
}

type rawInfo struct {
	GoVersion     string     `json:"version"`
	UserFunctions []Function `json:"UserFunctions"`
	StdFunctions  []Function `json:"StdFunctions"`
}

type Symbol struct {
	Offset uint64
	Name   string
}

type SymbolTable []Symbol // sorted

type G struct {
	Size    uint64
	Offsets map[string]uint64
}

func (g *G) FieldOffset(name string) uint64 {
	return g.Offsets[name]
}

type ELFInfo struct {
	GoVersion string
	SymbolTable
	GProto, AllgsProto *Proto
}

func (e *ELF) Parse() (elfInfo *ELFInfo, err error) {
	out, err := exec.Command("GoReSym", "-d", e.filename).Output()
	if err != nil {
		return nil, err
	}
	raw := &rawInfo{}
	if err = json.Unmarshal(out, raw); err != nil {
		return
	}
	elfInfo = &ELFInfo{GoVersion: raw.GoVersion}
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
	for _, f := range append(raw.UserFunctions, raw.StdFunctions...) {
		elfInfo.SymbolTable = append(elfInfo.SymbolTable,
			Symbol{
				Offset: f.Address - textSection.Addr + textSection.Offset,
				Name:   f.Name,
			})
	}
	slices.SortFunc(elfInfo.SymbolTable,
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
