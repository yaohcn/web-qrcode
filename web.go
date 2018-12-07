package main

import (
	"encoding/hex"
	"encoding/json"
	"fmt"
	"html/template"
	"io/ioutil"
	"log"
	"net/http"
	"strings"
	"time"
)

type conf struct {
	Addr string
}

func loadConf(c *conf) error {
	data, err := ioutil.ReadFile("./config.json")
	if err != nil {
		return err
	}
	return json.Unmarshal(data, c)
}
func parseData(w http.ResponseWriter, r *http.Request) {

	if r.Method == "GET" {
		t, _ := template.ParseFiles("submit.html")
		log.Println(t.Execute(w, nil))
	} else {
		data_hex, err := hex.DecodeString(strings.TrimSpace(r.FormValue("data")))
		if err != nil {
			fmt.Fprintf(w, err.Error())
			return
		}
		if len(data_hex) < 180 {
			fmt.Fprintf(w, "input data too short")
			return
		}
		if data_hex[0] == 0x02 || data_hex[0] == 0x54 {
			var qr qrcodeInfo
			err := aliAndOwnQrcodeParse(data_hex, &qr)
			if err != nil {
				fmt.Fprintf(w, err.Error())
				return
			}
			t, _ := template.New("qrcode.tmpl").Funcs(template.FuncMap{"timeString": timeString}).ParseFiles("qrcode.tmpl")
			log.Println(t.Execute(w, qr))

		} else if data_hex[0] >= 0x80 {
			fmt.Fprintf(w, "暂不支持交通部二维码")
			return
		} else if (data_hex[0] >> 4) == 2 {
			var re recordInfo
			err := aliAndOwnRecordParseV2(data_hex, &re)
			if err != nil {
				fmt.Fprintf(w, err.Error())
				return
			}
			t, _ := template.New("record.tmpl").Funcs(template.FuncMap{"timeString": timeString}).ParseFiles("record.tmpl")
			log.Println(t.Execute(w, re))
		} else if (data_hex[0] >> 4) == 1 {
			var re recordInfo
			err := aliAndOwnRecordParseV1(data_hex, &re)
			if err != nil {
				fmt.Fprintf(w, err.Error())
				return
			}
			t, _ := template.New("record.tmpl").Funcs(template.FuncMap{"timeString": timeString}).ParseFiles("record.tmpl")
			log.Println(t.Execute(w, re))
		} else if data_hex[0] == 0x00 && data_hex[1] == 0x00 {
			fmt.Fprintf(w, "暂不支持交通部record")
			return
		} else {
			var re recordInfo
			err := aliRecordParseV1(data_hex, &re)
			if err != nil {
				fmt.Fprintf(w, err.Error())
				return
			}
			t, _ := template.New("record.tmpl").Funcs(template.FuncMap{"timeString": timeString}).ParseFiles("record.tmpl")
			log.Println(t.Execute(w, re))
		}
	}
}
func timeString(unixtamp uint32) string {
	return time.Unix(int64(unixtamp), 0).Format("2006-01-02 15:04:05")
}
func main() {
	var c conf

	err := loadConf(&c)
	if err != nil {
		log.Fatal("loadConf: ", err)
	}

	http.HandleFunc("/", parseData)
	err = http.ListenAndServe(c.Addr, nil)
	if err != nil {
		log.Fatal("ListenAndServe: ", err)
	}
}
