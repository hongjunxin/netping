package main

import (
	"bytes"
	"os/exec"
	"strconv"
	"strings"

	log "github.com/sirupsen/logrus"
)

const (
	PORT_SENDER   = 10038 // todo: move to config
	PORT_RECEIVER = 10039

	QUEUE_NUM_SENDER   = 1048
	QUEUE_NUM_RECEIVER = 1049
)

var (
	recvQuit = make(chan bool)
	sendQuit = make(chan bool)
)

func setIptablesNFQ() error {
	if err := setIptablesNFQ_base(true); err != nil {
		return err
	}
	if err := setIptablesNFQ_base(false); err != nil {
		return err
	}
	return nil
}

func setIptablesNFQ_base(sender bool) error {
	var rule bytes.Buffer

	rule.WriteString(" PREROUTING -p tcp")
	rule.WriteString(" --sport ")
	if sender {
		rule.WriteString(strconv.Itoa(PORT_RECEIVER))
	} else {
		rule.WriteString(strconv.Itoa(PORT_SENDER))
	}

	rule.WriteString(" --dport ")
	if sender {
		rule.WriteString(strconv.Itoa(PORT_SENDER))
	} else {
		rule.WriteString(strconv.Itoa(PORT_RECEIVER))
	}

	rule.WriteString(" -j NFQUEUE --queue-num ")
	if sender {
		rule.WriteString(strconv.Itoa(QUEUE_NUM_SENDER))
	} else {
		rule.WriteString(strconv.Itoa(QUEUE_NUM_RECEIVER))
	}

	rulestr := rule.String()
	checkRule := "-t raw -C" + rulestr
	addRule := "-t raw -A" + rulestr

	log.Debugf("exec: iptables %v", checkRule)
	cmd := exec.Command("iptables", strings.Split(checkRule, " ")...)
	var stderr bytes.Buffer
	cmd.Stderr = &stderr
	if err := cmd.Run(); err != nil {
		// todo: un-linux is the same stderr msg?
		if strings.Contains(stderr.String(), "No chain/target/match") {
			log.Debugf("exec: iptables %v", addRule)
			cmd = exec.Command("iptables", strings.Split(addRule, " ")...)
			if err := cmd.Run(); err != nil {
				log.Errorf("iptables exec '%v' failed, stderr='%v'", addRule, stderr.String())
				return err
			}
		} else {
			log.Errorf("iptables exec '%v' failed, stderr='%v'", checkRule, stderr.String())
			return err
		}
	}

	rulestr = strings.Replace(rulestr, "tcp", "udp", 1)
	checkRule = "-t raw -C" + rulestr
	addRule = "-t raw -A" + rulestr

	log.Debugf("exec: iptables %v", checkRule)
	cmd = exec.Command("iptables", strings.Split(checkRule, " ")...)
	stderr.Reset()
	cmd.Stderr = &stderr
	if err := cmd.Run(); err != nil {
		// todo: un-linux is the same stderr msg?
		if strings.Contains(stderr.String(), "No chain/target/match") {
			log.Debugf("exec: iptables %v", addRule)
			cmd = exec.Command("iptables", strings.Split(addRule, " ")...)
			if err := cmd.Run(); err != nil {
				log.Errorf("iptables exec '%v' failed, stderr='%v'", addRule, stderr.String())
				return err
			}
		} else {
			log.Errorf("iptables exec '%v' failed, stderr='%v'", checkRule, stderr.String())
			return err
		}
	}

	return nil
}
