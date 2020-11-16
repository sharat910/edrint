package processor

import (
	"bufio"
	"encoding/json"
	"os"

	"github.com/rs/zerolog/log"
	"github.com/sharat910/edrint/events"
)

type Dumper struct {
	BaseSubscriber
	file   *os.File
	writer *bufio.Writer
	topics []events.Topic
}

func (d *Dumper) Teardown() {
	err := d.writer.Flush()
	if err != nil {
		log.Fatal().Err(err).Msg("unable to flush dump file")
	}
	err = d.file.Close()
	if err != nil {
		log.Fatal().Err(err).Msg("unable to close json dump file")
	}
	log.Info().Msg("dumper: flushed files")
}

type DumpItem struct {
	//Timestamp string
	Topic string
	Event interface{}
}

func NewDumper(path string, topics []events.Topic) *Dumper {
	var d Dumper
	//d.file = createFile(viper.GetString("processors.dump.path"))
	d.file = createFile(path)
	d.writer = bufio.NewWriter(d.file)
	d.topics = topics
	return &d
}

func (d *Dumper) Name() string {
	return "dump"
}

func (d *Dumper) Subs() []events.Topic {
	//topicstrings := viper.GetStringSlice("processors.dump.topics")
	//topics := make([]events.Topic, len(topicstrings))
	//for i, t := range topicstrings {
	//	topics[i] = events.Topic(t)
	//}
	return d.topics
}

func (d *Dumper) EventHandler(topic events.Topic, event interface{}) {
	b, err := json.Marshal(DumpItem{
		//Timestamp: time.Now().Format(time.RFC3339Nano),
		Topic: string(topic),
		Event: event,
	})
	if err != nil {
		log.Fatal().Err(err).Msg("unable to marshal json")
	}
	_, err = d.writer.Write(b)
	if err != nil {
		log.Fatal().Err(err).Msg("unable to write json")
	}

	_, err = d.writer.WriteRune('\n')
	if err != nil {
		log.Fatal().Err(err).Msg("unable to write newline")
	}
}
