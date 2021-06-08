package edrint

import (
	"fmt"
	"os"
	"path/filepath"
	"time"

	"github.com/rs/zerolog"
	"github.com/rs/zerolog/log"
)

func SetupLogging(l string) {
	zerolog.TimeFieldFormat = "2006-01-02 15:04:05.000000"
	consoleWriter := zerolog.ConsoleWriter{Out: os.Stdout, TimeFormat: "15:04:05.000"}
	logpath := filepath.Join("files", "logs", fmt.Sprintf("%s.log", time.Now().Format("2006-01-02")))
	file := createFile(logpath)
	multi := zerolog.MultiLevelWriter(consoleWriter, file)
	log.Logger = zerolog.New(multi).With().Timestamp().Logger()
	lvl, err := zerolog.ParseLevel(l)
	if err != nil {
		log.Fatal().Err(err).Msg("incorrect level")
	}
	zerolog.SetGlobalLevel(lvl)
	log.Info().Str("Level", l).Msg("Logging setup done")
}

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
