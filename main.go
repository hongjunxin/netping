package main

import (
	"os"
	"time"

	log "github.com/sirupsen/logrus"
)

func init() {
	log.SetFormatter(&log.TextFormatter{})
	// file, err := os.OpenFile("./debug.log", os.O_CREATE|os.O_WRONLY|os.O_APPEND, 0644)
	// if err == nil {
	// 	log.SetOutput(file)
	// } else {
	// 	log.Infof("main: using default stderr, error='%v'", err)
	// }
	log.SetLevel(log.DebugLevel)
	setIptablesNFQ()
}

func main() {
	var receiver Receiver
	if err := receiver.init(RECV_PING); err != nil {
		log.Errorf("main: receiver.init() failed, err=%v", err)
		os.Exit(1)
	}
	receiver.recv()

	for {
		time.Sleep(3 * time.Second)
	}
}
