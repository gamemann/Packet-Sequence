# Packet Sequence (WIP)
## Description
This is a tool that may be used to send single or multiple outbound packets in sequences. Each sequence may contain different packet characteristics and you may apply limits such as max packet count, time (in seconds), maximum data (in bytes) to each sequence.

**Note #1** - Please use this tool at your **own risk**. I am **not** responsible for any damage done and do **not** support using this tool for illegal operations such as targeted (D)DoS attacks. This tool was primarily made for pen-testing.

**Note #2** - This tool is still in development and I am working to add more features while maintaining high performance. The basic functionality should be working. I'm hoping to turn this tool into a network monitor tool by implementing sequence types that can receive specific packets and use the response in later sequences. With that said, I'd like to add an option to send HTTP/HTTPS requests if a receive sequence succeeds or fails after a specific timeout.

## Requirements
* [libyaml](https://github.com/yaml/libyaml) - A C library for parsing YAML config files.

## Usage
You may append `-h` when executing the application to see what command line parameters you may use. Please see below:

```
Usage: pcktseq -c <configfile> [-v -g -h]

-c --cfg => Path to YAML file to parse.
-g --global => N/A
-l --list => Print basic information about sequences.
-v --verbose => Provide verbose output.
-h --help => Print out help menu and exit program.
```

You may look at the `tests/` directory for some examples of YAML config files to use with this program. These config examples do not include all settings you can set with sequences and I will work on documenting the rest down later when the program is closer to official release.

[![demonstration](https://g.gflclan.com/3536-11-02-2020-0v94za6v.png)](https://www.youtube.com/watch?v=pLg_WMqwgzg)

## Compiling
You may use `make` to compile this program. This will compile `libyaml` as well. Please look at the below examples.

### Compiling Both LibYAML And The Program
```
# Clone the repo and libyaml via --recursive.
git clone --recursive https://github.com/gamemann/Packet-Sequence

# Go into directory.
cd Packet-Sequence

# Some needed tools for libyaml.
#apt-get install autoconf libtool

# Compile both libyaml and the program.
make
```

### Compiling Just The Program
```
# Clone the repo and libyaml via --recursive.
git clone --recursive https://github.com/gamemann/Packet-Sequence

# Go into directory.
cd Packet-Sequence

# Compile the program only.
make pcktsequence
```

## Credits
* [Christian Deacon](https://github.com/gamemann)