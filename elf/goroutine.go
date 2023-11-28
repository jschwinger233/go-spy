package elf

import "github.com/jschwinger233/go-spy/proc"

type Goroutine struct {
	Goid      int64
	Status    string
	Backtrace []string
}

func (e *ELFInfo) ParseSnapshot(snapshot *proc.Snapshot) (goroutines []*Goroutine, err error) {
	return
}
