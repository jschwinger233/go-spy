/*Copyright (C) 2022 Mandiant, Inc. All Rights Reserved.*/
package elf

import (
	"bytes"
	"fmt"
	"os"

	// we copy the go src directly, then change every include to github.com/jschwinger233/go-spy/elf/<whatever>
	// this is required since we're using internal files. Our modifications are directly inside the copied source

	"github.com/mandiant/GoReSym/objfile"
)

type FuncMetadata struct {
	Start    uint64
	End      uint64
	FullName string
}

type ExtractMetadata struct {
	Version   string
	Functions []FuncMetadata
}

func recoverMetadata(fileName string) (metadata ExtractMetadata, err error) {
	extractMetadata := ExtractMetadata{}

	file, err := objfile.Open(fileName)
	if err != nil {
		return ExtractMetadata{}, fmt.Errorf("invalid file: %w", err)
	}

	fileData, fileDataErr := os.ReadFile(fileName)
	if fileDataErr == nil {
		// GOVERSION
		if extractMetadata.Version == "" {
			idx := bytes.Index(fileData, []byte{0x67, 0x6F, 0x31, 0x2E})
			if idx != -1 && len(fileData[idx:]) > 10 {
				extractMetadata.Version = "go1."
				ver := fileData[idx+4 : idx+10]
				for i, c := range ver {
					// the string is _not_ null terminated, nor length delimited. So, filter till first non-numeric ascii
					nextIsNumeric := (i+1) < len(ver) && ver[i+1] >= 0x30 && ver[i+1] <= 0x39

					// careful not to end with a . at the end
					if (c >= 0x30 && c <= 0x39 && c != ' ') || (c == '.' && nextIsNumeric) {
						extractMetadata.Version += string([]byte{c})
					} else {
						break
					}
				}
			}
		}
	}

	tabs, err := file.PCLineTable("", 0, 0)
	if err != nil {
		return ExtractMetadata{}, fmt.Errorf("failed to read pclntab: %w", err)
	}

	if len(tabs) == 0 {
		return ExtractMetadata{}, fmt.Errorf("no pclntab candidates found")
	}

	var finalTab *objfile.PclntabCandidate = &tabs[0]
	for idx, tab := range tabs {
		foundMainMain, foundRuntimeGoexit := false, false
		for _, elem := range tab.ParsedPclntab.Funcs {
			if elem.Name == "main.main" {
				foundMainMain = true
				continue
			}
			if elem.Name == "runtime.goexit" {
				foundRuntimeGoexit = true
			}
		}
		if foundMainMain && foundRuntimeGoexit {
			finalTab = &tabs[idx]
			break
		}
	}

	for _, elem := range finalTab.ParsedPclntab.Funcs {
		extractMetadata.Functions = append(extractMetadata.Functions, FuncMetadata{
			Start:    elem.Entry,
			End:      elem.End,
			FullName: elem.Name,
		})
	}

	return extractMetadata, nil
}
