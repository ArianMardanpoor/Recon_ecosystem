#!/bin/bash
go build -o nice_passive nice_passive.go
go build -o nice_katana nice_katana.go
go build -o nice_params nice_params.go
go build -o x9 x9.go
go build -o xssniper xssniper.go
go build -o xsscanner main.go
go build -o dom_sink_checker dom_sink_checker.go
go build -o curl_reflect_checker curl_reflect_checker.go
echo "Build complete."
