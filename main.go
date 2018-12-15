package main

import (
	"encoding/binary"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"html/template"
	"log"
	"net/http"
	"strings"
)

func recordCorrect(w http.ResponseWriter, r *http.Request) {
	if r.Method == "GET" {
		t, _ := template.ParseFiles("correct.tmpl")
		log.Println(t.Execute(w, nil))
	}
	if r.Method == "POST" {
		record, err := hex.DecodeString(strings.TrimSpace(r.FormValue("record")))
		if err != nil {
			wr := wrongResponse{-1, err.Error()}
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
			wr := wrongResponse{-2, err.Error()}
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
			wr := wrongResponse{-10, err.Error()}
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
		rr := rightResponse{0, rec}
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
			var qr motQrcode
			err := motQrcodeParse(data_hex, &qr)
			if err != nil {
				fmt.Fprintf(w, err.Error())
				return
			}
			t, _ := template.New("motQrcode.tmpl").Funcs(template.FuncMap{"timeString": timeString}).ParseFiles("motQrcode.tmpl")
			log.Println(t.Execute(w, qr))
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
		} else if data_hex[0] == 0x00 {
			//} else if data_hex[0] == 0x00 && data_hex[1] == 0x00 {
			var re motRecord
			err := motRecordParse(data_hex, &re)
			if err != nil {
				fmt.Fprintf(w, err.Error())
				return
			}
			if re.ProtoType == "支付宝" {
				t, _ := template.New("motAliRecord.tmpl").Funcs(template.FuncMap{"timeString": timeString}).ParseFiles("motAliRecord.tmpl")
				log.Println(t.Execute(w, re))
			} else {
				t, _ := template.New("motRecord.tmpl").Funcs(template.FuncMap{"timeString": timeString}).ParseFiles("motRecord.tmpl")
				log.Println(t.Execute(w, re))
			}

		} else {
			fmt.Fprintf(w, "proto not detect")
			return
		}
	}
}
func main() {
	var c conf

	err := loadConf(&c)
	if err != nil {
		log.Fatal("loadConf: ", err)
	}

	http.HandleFunc("/", parseData)
	http.HandleFunc("/record", recordCorrect)

	err = http.ListenAndServe(c.Addr, nil)
	if err != nil {
		log.Fatal("ListenAndServe: ", err)
	}
}
