package processor

import (
	"os"
	"path/filepath"

	"github.com/rs/zerolog/log"
)

func createDirs(filePath string) {
	//Creating directories
	directorystring := filepath.Dir(filePath)
	err := os.MkdirAll(directorystring, os.ModePerm)
	if err != nil {
		log.Fatal().Err(err).Msg("cannot create directories")
	}
}

func createFile(filePath string) *os.File {
	//Creating file
	createDirs(filePath)
	file, err := os.Create(filePath)
	if err != nil {
		log.Fatal().Err(err).Msg("cannot create file")
	}
	return file
}
