// Copyright 2012, Matias Pablo Brutti  All rights reserved.
//
// N.W.A. is free software: you can redistribute it and/or modify it under
// the terms of version 3 of the GNU Lesser General Public License as
// published by the Free Software Foundation.
//
// N.W.A. is distributed in the hope that it will be useful, but WITHOUT ANY
// WARRANTY; without even the implied warranty of MERCHANTABILITY or FITNESS
// FOR A PARTICULAR PURPOSE.  See the GNU Lesser General Public License for
// more details.
//
// You should have received a copy of the GNU Lesser General Public License
// along with ESearchy.  If not, see <http://www.gnu.org/licenses/>.

package main

import (
	"./nmap"
	"fmt"
	goopt "github.com/droundy/goopt"
	"net/http"
	"strconv"
	"strings"
	"text/template"
)

const (
	Reset   = "\x1b[0m"
	Black   = "\x1b[30m"
	Red     = "\x1b[31m"
	Green   = "\x1b[32m"
	Yellow  = "\x1b[33m"
	Blue    = "\x1b[34m"
	Magenta = "\x1b[35m"
	Cyan    = "\x1b[36m"
	White   = "\x1b[37m"
)

func portResults(rw http.ResponseWriter, req *http.Request) {
	req.ParseForm()
	t := template.New("list.html")
	t.ParseFiles("web/list.html")
	list_type := req.FormValue("type")
	switch list_type {
	case "port":
		t.Execute(rw, v.OpenPorts())
	case "os":
		t.Execute(rw, v.OSList())
	default:
		t.Execute(rw, []nmap.OpenList{})
	}

}

func SearchHandler(rw http.ResponseWriter, req *http.Request) {
	req.ParseForm()
	search_type := req.FormValue("type")
	query := req.FormValue("query")
	t := template.New("nmap.html")
	t.ParseFiles("web/nmap.html")
	switch search_type {
	case "os":
		t.Execute(rw, v.WithOS(query))
	case "service":
		t.Execute(rw, v.WithService(query))
	case "banner":
		t.Execute(rw, v.WithBanner(query))
	case "port":
		t.Execute(rw, v.WithOpenPort(query))
	default:
		t.Execute(rw, []nmap.Host{})
	}
}

func nmapResults(rw http.ResponseWriter, req *http.Request) {
	req.ParseForm()
	t := template.New("nmap.html")
	t.ParseFiles("web/nmap.html")
	hosts := v.Alive()
	maxsize := len(hosts)

	start, err := strconv.Atoi(req.FormValue("start"))
	if err != nil {
		t.Execute(rw, hosts[0:49])
	} else {
		if start <= maxsize-50 {
			t.Execute(rw, hosts[start:start+49])
		} else {
			if start < maxsize {
				t.Execute(rw, hosts[start:maxsize])
			} else {
				t.Execute(rw, hosts[maxsize-50:maxsize])
			}
		}
	}
}

func nmapAllResults(rw http.ResponseWriter, req *http.Request) {
	t := template.New("nmap.html")
	t.ParseFiles("web/nmap.html")
	t.Execute(rw, v.Alive())
}

func nmapIPInfo(rw http.ResponseWriter, req *http.Request) {
	ip := req.URL.Path[lenPath:]
	t := template.New("host.html")
	t.ParseFiles("web/host.html")

	for _, host := range v.Alive() {
		if host.Address.Addr == ip {
			t.Execute(rw, host)
		}
	}
}

func nmapIPInfojson(rw http.ResponseWriter, req *http.Request) {
	ip := req.URL.Path[len("/json/"):]
	nodes := []string{}
	links := []string{}
	for _, host := range v.Alive() {
		if host.Address.Addr == ip {
			for i, h := range host.Trace.Hops {
				nodes = append(nodes, fmt.Sprintf("{\"group\":%s , \"name\": \"%s\", \"rtt\": \"%s\" }", h.Ttl, h.IPAddr, h.Rtt))
				links = append(links, fmt.Sprintf("{\"source\":%d,\"target\":%d,\"value\":%s}", i, i+1, h.Rtt))
			}
		}
	}
	fmt.Fprintf(rw, "{ \"nodes\":\n [\n%s\n]\n,\"links\":\n [\n%s\n]\n}", strings.Join(nodes, ",\n"), strings.Join(links[0:len(links)-1], ",\n"))
}

var v = nmap.Scan{}

const lenPath = len("/ip/")

var nmapfile = goopt.String([]string{"-v", "--file"},
	"", "Name of the .xml nmap file")

func main() {
	goopt.Description = func() string {
		return "Pretty Pringing Nmap Web App Viewer"
	}
	goopt.Version = "1.0"
	goopt.Summary = "convert .xml to .html pretty format"
	goopt.Parse(nil)

	if *nmapfile != "" {
		fmt.Printf("Processing nmap (%s).\n", *nmapfile)
		go nmap.Parse(&v, *nmapfile)
		fmt.Print("Hosting Nmap results in http://localhost:8080\n")

		// Static Files
		http.Handle("/js/", http.StripPrefix("/js/",
			http.FileServer(http.Dir("./web/js"))))
		http.Handle("/css/", http.StripPrefix("/css/",
			http.FileServer(http.Dir("./web/css"))))
		http.Handle("/images/", http.StripPrefix("/images/",
			http.FileServer(http.Dir("./web/images"))))

		// Dinamic Content
		http.HandleFunc("/", nmapResults)
		http.HandleFunc("/all", nmapAllResults)
		http.HandleFunc("/ip/", nmapIPInfo)
		http.HandleFunc("/json/", nmapIPInfojson)
		http.HandleFunc("/list", portResults)
		http.HandleFunc("/search", SearchHandler)

		//Launch web server in 8080
		http.ListenAndServe(":8080", nil)
	} else {
		return
	}
}
