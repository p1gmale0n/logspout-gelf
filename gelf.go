package gelf

import (
	"encoding/json"
	"errors"
	"log"
	"os"
	"strings"
	"time"

	"github.com/Graylog2/go-gelf/gelf"
	"github.com/gliderlabs/logspout/router"
)

var hostname string
var multilineStart, multilineEnd []string

func init() {
	hostname, _ = os.Hostname()
	multilineStart = strings.Split(os.Getenv("multiline_start"), ":")
	multilineEnd = strings.Split(os.Getenv("multiline_end"), ":")
	router.AdapterFactories.Register(NewGelfAdapter, "gelf")
}

// GelfAdapter is an adapter that streams UDP JSON to Graylog
type GelfAdapter struct {
	writer *gelf.Writer
	route  *router.Route
}

// NewGelfAdapter creates a GelfAdapter with UDP as the default transport.
func NewGelfAdapter(route *router.Route) (router.LogAdapter, error) {
	_, found := router.AdapterTransports.Lookup(route.AdapterTransport("udp"))
	if !found {
		return nil, errors.New("unable to find adapter: " + route.Adapter)
	}

	gelfWriter, err := gelf.NewWriter(route.Address)
	if err != nil {
		return nil, err
	}

	return &GelfAdapter{
		route:  route,
		writer: gelfWriter,
	}, nil
}

// Stream implements the router.LogAdapter interface.
func (a *GelfAdapter) Stream(logstream chan *router.Message) {
	record := make(map[string]string)
	for message := range logstream {
		m := &GelfMessage{message}
		level := gelf.LOG_INFO
		if m.Source == "stderr" {
			level = gelf.LOG_ERR
		}
		if m.Message.Data == "" {
			continue
		}
		unixTime := float64(m.Message.Time.UnixNano()/int64(time.Millisecond)) / 1000.0
		extra, err := m.getExtraFields()
		if err != nil {
			log.Println("Graylog:", err)
			continue
		}

		if _, ok := record[m.Container.Name]; ok {
			record[m.Container.Name] = record[m.Container.Name] + m.Message.Data + "\n"
		} else if (stringInSlice(m.Message.Data, multilineStart)) && (stringInSlice(m.Message.Data, multilineEnd)) {
			sendGelfMessage(a, hostname, m.Message.Data, level, unixTime, extra)
			continue
		} else if stringInSlice(m.Message.Data, multilineStart) {
			record[m.Container.Name] = m.Message.Data + "\n"
			continue
		}

		if stringInSlice(m.Message.Data, multilineEnd) {
			sendGelfMessage(a, hostname, record[m.Container.Name], level, unixTime, extra)
			delete(record, m.Container.Name)
			continue
		} else if _, ok := record[m.Container.Name]; ok != true {
			sendGelfMessage(a, hostname, m.Message.Data, level, unixTime, extra)
		}

		// msg := gelf.Message{
		// 	Version:  "1.1",
		// 	Host:     hostname,
		// 	Short:    m.Message.Data,
		// 	TimeUnix: float64(m.Message.Time.UnixNano()/int64(time.Millisecond)) / 1000.0,
		// 	Level:    level,
		// 	RawExtra: extra,
		// }
		// 	ContainerId:    m.Container.ID,
		// 	ContainerImage: m.Container.Config.Image,
		// 	ContainerName:  m.Container.Name,
		// }

		// here be message write.
		// if err := a.writer.WriteMessage(&msg); err != nil {
		// 	log.Println("Graylog:", err)
		// 	continue
		// }
	}
}

type GelfMessage struct {
	*router.Message
}

func sendGelfMessage(a *GelfAdapter, hostname string, message string, level int32, unixTime float64, extra json.RawMessage) {
	msg := gelf.Message{
		Version:  "1.1",
		Host:     hostname,
		Short:    message,
		TimeUnix: unixTime,
		Level:    level,
		RawExtra: extra,
	}
	if err := a.writer.WriteMessage(&msg); err != nil {
		log.Println("Graylog:", err)
	}
}

func stringInSlice(a string, list []string) bool {
	for _, b := range list {
		if strings.Contains(a, b) {
			return true
		}
	}
	return false
}

func (m GelfMessage) getExtraFields() (json.RawMessage, error) {

	extra := map[string]interface{}{
		"_container_id":   m.Container.Name,
		"_container_name": m.Container.Name[1:], // might be better to use strings.TrimLeft() to remove the first /
		"_image_id":       m.Container.Image,
		"_image_name":     m.Container.Config.Image,
		"_command":        strings.Join(m.Container.Config.Cmd[:], " "),
		"_created":        m.Container.Created,
	}
	for name, label := range m.Container.Config.Labels {
		if len(name) > 5 && strings.ToLower(name[0:5]) == "gelf_" {
			extra[name[4:]] = label
		}
	}
	swarmnode := m.Container.Node
	if swarmnode != nil {
		extra["_swarm_node"] = swarmnode.Name
	}

	rawExtra, err := json.Marshal(extra)
	if err != nil {
		return nil, err
	}
	return rawExtra, nil
}
