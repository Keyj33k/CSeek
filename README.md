<div align="center">

![version](https://img.shields.io/badge/Version-0.0.3-informational?style=flat&logo=&logoColor=white&color=red) ![stars](https://img.shields.io/github/stars/Keyj33k/cseek-ClientIdentifier-Python?style=social) ![forks](https://img.shields.io/github/forks/Keyj33k/cseek-ClientIdentifier-Python?label=Forks&logo=&logoColor=white&color=blue) ![languages](https://img.shields.io/github/languages/count/Keyj33k/cseek-ClientIdentifier-Python?style=social&logo=&logoColor=white&color=blue) ![issues](https://img.shields.io/github/last-commit/Keyj33k/cseek-ClientIdentifier-Python?style=flat&logo=&logoColor=white&color=blue) ![platform](https://img.shields.io/badge/Platform-Linux/Windows-informational?style=flat&logo=&logoColor=white&color=green) 

<a href="https://github.com/Keyj33k/cseek-ClientIdentifier-Python/archive/refs/heads/main.zip"><img src="https://github.com/Keyj33k/cseek-ClientIdentifier-Python/blob/main/img/cseek_banner.svg" alt="banner"/></a>
  
</div>

## cseekers Mission
- scan address range in local network to detect reachable devices<br>
- optional port scanning config for live hosts and determining of services behind open ports<br>
- store succeed results to a file for saving a detailed summary<br>

## :rocket: Getting Started: 

1 ) Make sure, you have `python` installed:
```
python3 --version
```
2 ) If it isn't installed (Debian/-based):
```
sudo apt-get install python3
```
3 ) Clone the repository:
```
git clone https://github.com/Keyj33k/cseek-ClientIdentifier-Python.git
```
4 ) `Run cseek` using the following command:
```
python3 cseek.py -h
```

## Options/Usage

```
usage: cseek.py [-h] [-u] -a address -b begin_host -f final_host [-s start_port] [-l last_port] [-c ping_count]
example: cseek.py -a 192.168.2 -b 1 -f 100 -c 1 --unlock -s 10 -l 90 

cseek - Network Client Identifier

options:
  -h, --help            show this help message and exit
  -u, --unlock          unlock port scanning
  -a address, --addr address
                        address to ping (first three octets only)
  -b begin_host, --begin begin_host
                        host where the scan should start
  -f final_host, --final final_host
                        host where the scan should end
  -s start_port, --start start_port
                        port where the scan should start
  -l last_port, --last last_port
                        port where the scan should end
  -c ping_count, --count ping_count
                        determine ping count

```

<div align="center">
  
### The Output Will Be Stored In A Text File: `/output/cseek_output.txt`

</div>

## 🎬 cseek Output Example
<div align="center">
  
![demo](https://github.com/Keyj33k/cseek-ClientIdentifier-Python/blob/main/img/cseek_output_example.png?raw=true)
  
</div>

## My Motivation
In most cases I used a simple bash script to start the recon session to learn about the network of the <br> 
current pentest. It's a really good method to getting started, but for bigger ranges it's nearly <br> 
impossible to keep the overview. If the Bash script located active devices, I had to do a port scan on <br> 
each hosts separately. While this process, the workspace looked very messy and the overview was lost quickly. <br> 
In a nutshell, I wanted to create a tool that would do all these things itself and simply save all active <br> 
devices and their associated open ports to one file. If cseek stored the results, I know where i need to begin <br>
my next steps without loosing much time and keep a clear workspace too. 

## Feedback And Bug Report

If you found a bug, or wanna start a discussion, please use ![Github issues](https://github.com/Keyj33k/cseek-ClientIdentifier-Python/issues). You are also invited to <br>
send an email to the following address: `nomotikag33n@gmail.com`

## LICENSE
```
Copyright (c) 2022 Keyjeek

Permission is hereby granted, free of charge, to any person obtaining a copy
of this software and associated documentation files (the "Software"), to deal
in the Software without restriction, including without limitation the rights
to use, copy, modify, merge, publish, distribute, sublicense, and/or sell
copies of the Software, and to permit persons to whom the Software is
furnished to do so, subject to the following conditions:

The above copyright notice and this permission notice shall be included in all
copies or substantial portions of the Software.

THE SOFTWARE IS PROVIDED "AS IS", WITHOUT WARRANTY OF ANY KIND, EXPRESS OR
IMPLIED, INCLUDING BUT NOT LIMITED TO THE WARRANTIES OF MERCHANTABILITY,
FITNESS FOR A PARTICULAR PURPOSE AND NONINFRINGEMENT. IN NO EVENT SHALL THE
AUTHORS OR COPYRIGHT HOLDERS BE LIABLE FOR ANY CLAIM, DAMAGES OR OTHER
LIABILITY, WHETHER IN AN ACTION OF CONTRACT, TORT OR OTHERWISE, ARISING FROM,
OUT OF OR IN CONNECTION WITH THE SOFTWARE OR THE USE OR OTHER DEALINGS IN THE
SOFTWARE.
```

---

<div align="center">

### Tested on 5.15.0-48-generic-Ubuntu

</div>

---




