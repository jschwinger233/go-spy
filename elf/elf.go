package elf

import "fmt"

type ELF struct {
	filename string
}

func GetFromPid(pid int) *ELF {
	return &ELF{filename: fmt.Sprintf("/proc/%d/exe", pid)}
}
