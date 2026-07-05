# Strace-converter-rs

This is a converter capable of parsing [Strace v6.17](https://github.com/strace/strace) log output for converting to [Trace Event Format (TEF)](https://docs.google.com/document/d/1CvAClvFfyA5R-PhYUmn5OOQtYMH4h6I0nSsKchNAySU/preview?tab=t.0#heading=h.yr4qxyxotyw). 

## Functionality

- Parse output to Trace Event Format 
- Generate graph data in CSV format
- Merging unfinished and resumed system calls 
- Simple argument parsing capabilities, including argument names

## Use cases

- Upload .tef files to [Perfetto UI](https://github.com/google/perfetto). 
- Import graph data into graph databases: I have another [project](https://github.com/m-wimmer/strace-sodg-visualizer-plugin) which utilises the CSV output. 

## Usage

Run Strace using the following options for generating compatible traces:

```sh
strace -yy --decode-pids=all --always-show-pid -T -tttN -s 100 -f -qqq -o curl.strace curl example.com
```

Traces can then be converted like this:

```sh
strace-converter-rs -i curl.strace -o curl-converted -f tef-csv
```

You can choose if you want TEF output and graph data or only one of them. Output:

```
|__ curl-converted.tef
|__ curl-converted-nodes.csv
|__ curl-converted-edges.csv
```
