package main

import (
	"bytes"
	"crypto/hmac"
	"crypto/md5"
	"encoding/binary"
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

type WrongResponse struct {
	Code    int    `json:"code"`
	Message string `json:"message"`
}
type RightResponse struct {
	Code   int    `json:"code"`
	Record string `json:"record"`
}

func makeRecord(qr []byte, posParam string, f *qrcodeInfo) string {
	version := "0000.0.20180104"

	tmp := make([]byte, 2)
	tmp1 := make([]byte, 4)

	var b bytes.Buffer

	recordVersion := 2
	recordLen := 2 + len(qr) + 2 + len(posParam) + 2 + 4 + 2 + len(version) + 2 + 16
	var head uint16
	head = uint16(recordVersion)<<12 | uint16(recordLen)
	binary.BigEndian.PutUint16(tmp, head)
	b.Write(tmp)

	binary.BigEndian.PutUint16(tmp, uint16(len(qr)))
	b.Write(tmp)

	b.Write(qr)

	binary.BigEndian.PutUint16(tmp, uint16(len(posParam)))
	b.Write(tmp)
	b.Write([]byte(posParam))

	binary.BigEndian.PutUint16(tmp, uint16(4))
	b.Write(tmp)
	binary.BigEndian.PutUint32(tmp1, f.QrcodeGeneTime+3)
	b.Write(tmp1)

	binary.BigEndian.PutUint16(tmp, uint16(len(version)))
	b.Write(tmp)
	b.Write([]byte(version))

	mac := hmac.New(md5.New, []byte(f.UserId))
	mac.Write(b.Bytes())
	expectedMAC := mac.Sum(nil)

	binary.BigEndian.PutUint16(tmp, uint16(len(expectedMAC)))
	b.Write(tmp)
	b.Write(expectedMAC)

	return hex.EncodeToString(b.Bytes())

}

func recordChange(w http.ResponseWriter, r *http.Request) {
	if r.Method == "GET" {
		t, _ := template.ParseFiles("change.html")
		log.Println(t.Execute(w, nil))
	}
	if r.Method == "POST" {
		record, err := hex.DecodeString(strings.TrimSpace(r.FormValue("record")))
		if err != nil {
			wr := WrongResponse{-1, err.Error()}
			js, err := json.Marshal(wr)
			if err != nil {
				http.Error(w, err.Error(), http.StatusInternalServerError)
				return
			}
			w.Header().Set("Content-Type", "application/json")
			w.Write(js)
			return
		}
		posParam := strings.TrimSpace(r.FormValue("posparam"))
		if err != nil {
			wr := WrongResponse{-2, err.Error()}
			js, err := json.Marshal(wr)
			if err != nil {
				http.Error(w, err.Error(), http.StatusInternalServerError)
				return
			}
			w.Header().Set("Content-Type", "application/json")
			w.Write(js)
			return
		}
		qrcodeLen := int(binary.BigEndian.Uint16(record[2:4]))
		qrcode := record[4 : 4+qrcodeLen]
		var f qrcodeInfo
		err = aliQrcodeParse(qrcode, &f)
		if err != nil {
			wr := WrongResponse{-10, err.Error()}
			js, err := json.Marshal(wr)
			if err != nil {
				http.Error(w, err.Error(), http.StatusInternalServerError)
				return
			}
			w.Header().Set("Content-Type", "application/json")
			w.Write(js)
			return
		}
		rec := makeRecord(qrcode, posParam, &f)
		rr := RightResponse{0, rec}
		js, err := json.Marshal(rr)
		if err != nil {
			http.Error(w, err.Error(), http.StatusInternalServerError)
			return
		}
		w.Header().Set("Content-Type", "application/json")
		w.Write(js)
		return
	}
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
	http.HandleFunc("/record", recordChange)

	err = http.ListenAndServe(c.Addr, nil)
	if err != nil {
		log.Fatal("ListenAndServe: ", err)
	}
}
