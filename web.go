package main

import (
	"encoding/hex"
	"fmt"
	"html/template"
	"log"
	"net/http"
	"strings"
)

func sayhelloName(w http.ResponseWriter, r *http.Request) {
	r.ParseForm()       //解析参数，默认是不会解析的
	fmt.Println(r.Form) //这些信息是输出到服务器端的打印信息
	fmt.Println("path", r.URL.Path)
	fmt.Println("scheme", r.URL.Scheme)
	fmt.Println(r.Form["url_long"])
	for k, v := range r.Form {
		fmt.Println("key:", k)
		fmt.Println("val:", strings.Join(v, ""))
	}
	fmt.Fprintf(w, "Hello astaxie!") //这个写入到w的是输出到客户端的
}
func qrcode(w http.ResponseWriter, r *http.Request) {
	fmt.Println("method:", r.Method) //获取请求的方法
	if r.Method == "GET" {
		t, _ := template.ParseFiles("qrcode.html")
		log.Println(t.Execute(w, nil))
	} else {
		var record recordInfo
		var f qrcodeInfo
		err := parse(r.FormValue("qrcode"), &record, &f)
		if err != nil {
			fmt.Fprintf(w, err.Error())
		}
		t, _ := template.ParseFiles("afterParse.html", "qrcode.html")
		log.Println(t.Execute(w, record))
		// fmt.Fprintf(w, record.TerminalInfo)
	}
}
func parse(data string, r *recordInfo, f *qrcodeInfo) error {
	data_hex, err := hex.DecodeString(data)
	if err != nil {
		log.Fatal(err)
	}
	err = recordParse(data_hex, r)
	if err != nil {
		return err
	}
	err = qrcodeParse(r.qrcode, f)
	if err != nil {
		return err
	}
	return nil
}
func main() {
	http.HandleFunc("/", sayhelloName) //设置访问的路由
	http.HandleFunc("/qrcode", qrcode)
	err := http.ListenAndServe(":9090", nil) //设置监听的端口
	if err != nil {
		log.Fatal("ListenAndServe: ", err)
	}
}
