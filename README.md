*Learning C purpose*
# malefik
Malicious LKM for multiple kernel, simple rootkit (bitflip, hidep, SIGRAPE, ...)

### on 5.10 kernel (Debian 11)

Working Gracefully !!!

### on 4.19 kernel (Debian 10)

Working Gracefully !!!

### on 4.9 kernel (Debian 9)

Kernel kill me


## Usage :

malefik redirect some kill signals to do something special things for you UwU.

Such as;
```
kill -64 <pid> : Escalate to root shell.
kill -31 <pid> : Hide/unhide process.
kill -32 1     : Hide and protect malefik rootkit.
kill -33 1     : Unhide and unprotect malefik rootkit.
```
