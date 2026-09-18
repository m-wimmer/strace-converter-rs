# Strace-converter-rs

This is a converter capable of parsing [Strace v6.17](https://github.com/strace/strace) log output for converting to [Trace Event Format (TEF)](https://docs.google.com/document/d/1CvAClvFfyA5R-PhYUmn5OOQtYMH4h6I0nSsKchNAySU/preview?tab=t.0#heading=h.yr4qxyxotyw). 

_Note: It probably also works for versions upwards of 6.17, but I did most of my testing using this version. However, versions below 6.16 won't work due to the missing -N option (Argument name decoding)._

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
_Note: Conversion requires all the previously specified arguments except -s. Theoretically -f and -o could also be omitted if --always-show-pid is
specified. If you don't want argument names decoded or other options, you'll have to look for another conversion utility._

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

## Contributing

Feel free to add issues for things that are wrong or should be added. I will be working on improving the utility further. Take a look at the open issues to see what I am working on next.

