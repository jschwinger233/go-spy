package elf

type ELFInfo struct {
	GoVersion string            // 1.20.0
	BuildMode string            // exe, pie
	SymbolMap map[uint64]string // offset -> symbol
}

func (elf *ELF) Parse() (*ELFInfo, error) {
	return &ELFInfo{GoVersion: "1.20.0", BuildMode: "exe", SymbolMap: map[uint64]string{0x1000: "main.main"}}, nil
}
