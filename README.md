# Simple tool to forward output of a command to an IRC channel

Usage example:

```
journalctl -fq | ircpipe --irc-server 192.168.0.10:6697 --use-tls --nick logbot --channel logs
```
