package processor

import (
	"bufio"
	"encoding/json"
	"os"

	"github.com/rs/zerolog/log"
	"github.com/sharat910/edrint/eventbus"
	"github.com/spf13/viper"
)

type Dumper struct {
	BaseSubscriber
	file   *os.File
	writer *bufio.Writer
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
}

type DumpItem struct {
	//Timestamp string
	Topic string
	Event interface{}
}

func NewDumper() *Dumper {
	var d Dumper
	d.file = createFile(viper.GetString("processors.dump.path"))
	d.writer = bufio.NewWriter(d.file)
	return &d
}

func (d *Dumper) Name() string {
	return "dump"
}

func (d *Dumper) Subs() []eventbus.Topic {
	topicstrings := viper.GetStringSlice("processors.dump.topics")
	topics := make([]eventbus.Topic, len(topicstrings))
	for i, t := range topicstrings {
		topics[i] = eventbus.Topic(t)
	}
	return topics
}

func (d *Dumper) EventHandler(topic eventbus.Topic, event interface{}) {
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
