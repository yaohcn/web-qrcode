package main

import (
	"crypto/hmac"
	"crypto/md5"
	"encoding/json"
	"io/ioutil"
	"time"
)

type wrongResponse struct {
	Code    int    `json:"code"`
	Message string `json:"message"`
}
type rightResponse struct {
	Code   int    `json:"code"`
	Record string `json:"record"`
}
type conf struct {
	Addr string
}

func timeString(unixtamp uint32) string {
	return time.Unix(int64(unixtamp), 0).Format("2006-01-02 15:04:05")
}
func loadConf(c *conf) error {
	data, err := ioutil.ReadFile("./config.json")
	if err != nil {
		return err
	}
	return json.Unmarshal(data, c)
}
func checkMAC(message, messageMAC, key []byte) bool {
	mac := hmac.New(md5.New, key)
	mac.Write(message)
	expectedMAC := mac.Sum(nil)
	return hmac.Equal(messageMAC, expectedMAC)
}
