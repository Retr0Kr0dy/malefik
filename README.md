*Learning C purpose* 
# <b>malefik</b> 
Malicious LKM, simple rootkit for studiying purpose [...].

## Affected vesion :
|kernel ver.|state|
|-|-|
|`5.10`|affected|
|`4.19`|affected|
|`4.15`|affected|
|`4.9`|affected|

## Install :
### `!!! TEMP !!!`
Install linux headers for your version, check it with `uname -r`.

With apt (debian, ...)
```sh
sudo apt install linux-headers-$(uname -r)
```
With dnf (fedora, ...)
```sh
 sudo dnf install kernel-headers
```

### `!!! ENDTEMP !!!`
Install with
```sh
sudo make
```
For debug mode (verbose)
```sh
sudo make debug
```
For cleaning
```sh
sudo make clean
```

## Usage :
malefik redirect some kill signals to do something special things for you UwU.

Such as
```
kill -64 <pid> : Escalate to root shell.
kill -31 <pid> : Hide/unhide process.
kill -32 1     : Hide and protect malefik rootkit.
kill -33 1     : Unhide and unprotect malefik rootkit.
```
