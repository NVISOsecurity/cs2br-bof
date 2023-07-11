# CS2BR BOF

You would like to execute BOFs written for Cobalt Strike in Brute Ratel C4? Look no further, we got you covered! CS2BR implements a compatibility-layer that make CS BOFs use the BRC4 API. This allows you to use the vast landscape that is BOFs in BRC4.

_Please read about its [caveats](#caveats) before using CS2BR._

## The Problem

As the BRC4 documentation on [coffexec](https://bruteratel.com/tabs/badger/commands/coffexec/) describes, porting CS BOFs to BR is a straight-forward task: all that needs to be done is replacing the name of CS's `go` entrypoint to BRC4's `coffee` and replacing CS's API calls to the BRC4 equivalents. For some simple API calls this is trivial (e.g. you can replace `BeaconPrintf` with `BadgetDispatch`).

However there are several sub-APIs in [CS's BOF C API](https://hstechdocs.helpsystems.com/manuals/cobaltstrike/current/userguide/content/topics/beacon-object-files_main.htm) that make this a more elaborate task:

* The `Data Parser API` provides utilities to parse data passed to the BOF. BRC4 doesn't have an equivalent for this as arguments are passed to BOFs as simple strings (using the `char** argv, int argc` parameters in the entrypoint).
* The `Format API` allows BOFs to format output in buffers for later transmission. BRC4 doesn't currently have an equivalent API.
* The `Internal API` features several utilities related to user impersonation, privileges and process injection. BRC4 doesn't currently have an equivalent API.

## Caveats

CS2BR is not a silver bullet that solves the problem of CS and BRC4 BOF incompatibility. There are a couple of caveats one should consider when utilizing CS2BR:

* CS2BR (*currently*) works only on a source code level: if you want to patch a BOF that you don't have source code for, CS2BR won't be of use to you.
* Patching the compatibility layer into source code results in more code getting generated, thus increasing the size of the compiled BOF. Also note that the compatibility layer code can get flagged in the future.
* CS2BR does not (*yet*) support all of CS's BOF C API: namely the `Internal API` is populated with stubs only and won't do anything. This mainly concerns BOFs utilizing CS's user impersonation and process injection API calls.
* While CS2BR allows you to pass parameters to BOFs, you'll still have to work out the number and type of parameters yourself by dissecting your BOF's CNA.

# Usage

There are three steps to using CS2BR:

1. [Patching](#1-patching-bof-source-code): Patch CS2BR compatibility-layer into BOF source code
2. Compile the BOF as instructed by the BOF authors
3. (Optionally)[Parameters](#3-generating-bof-parameters): Generate parameters to pass to a BOF
4. Execute BOF using `coffexec` in BRC4

## 1. Patching BOF source code

There are two options to patch BOF source code: you can either do this yourself of have the Python patching script do the job.

### Manual patching

1. Find the `beacon.h` file that contains the CS BOF C API definitions (ref. [beacon.h](https://hstechdocs.helpsystems.com/manuals/cobaltstrike/current/userguide/content/beacon.h))
2. Replace its contents with [beacon_wrapper.h](beacon_wrapper.h)'s contents.
3. Find the file containing the `go` entrypoint.
4. Rename the `go` entrypoint to `csentry`
5. Append the contents of [badger_stub.c](badger_stub.c) to the file.

### Patching script

Run [patch.py](patch.py) (requires Python 3):

```
usage: patch [-h] [--src SRC] [--beaconh BEACONH] [--entrypoint ENTRYPOINT] [--forcepatch] [--dry]

Patches Cobalt Strike BOF source code to be compatible with BruteRatel

options:
  -h, --help            show this help message and exit
  --src SRC             Directory of source code to patch (default: current working dir ,currently ".")
  --beaconh BEACONH     Name/pattern of or path to the headerfile(s) with Cobalt Strike beacon definitions to patch (default: "beacon.h")
  --entrypoint ENTRYPOINT
                        Name or pattern of the source file that contains the Cobalt Strike "go" entrypoint (default: "*.c", so any C source file).
  --forcepatch          Force patching already patched files
  --dry                 Dry-run: don't actually patch any files.
```

Example: `./patch.py --src /path/to/CS-Situational-Awareness-BOF` (to patch [trustedsec's Situational Awareness BOFs](https://github.com/trustedsec/CS-Situational-Awareness-BOF))

## 3. Generating BOF parameters

CS's `Data Parse API` allows passing arbitrary data to BOFs, including integers and binary blobs. BRC4 however can't pass arbitrary binary data to BOFs but only provides passing strings. 

To workaround this, CS2BR's compatibility-layer takes base64 encoded input and feeds this to the `Data Parse API`. However BRC4 doesn't feature aggressor scripts (CNA scripts) that query user inputs. CS2BR comes with [encode_args.py](encode_args.py) that allows you to enter parameters and generates the base64 string you can pass to your BOF in BRC4.

For example, here a base64 string is built using `encode_args.py` that can be consumed by the `Data Parse API` through CS2BR:

```
./encode_args.py

Documented commands (type help <topic>):
========================================
addString  addWString  addint  addshort  exit  generate  help  reset

BOF parameter encoder
CMD> addString localhost
CMD> generate
CgAAAGxvY2FsaG9zdAA=
CMD> exit
```

Alternatively, you can use `encode_args.py` non-interactively by passing pairs of `<type>:<value>` arguments to it, e.g.:
```
./encode_args.py "z:my first string" "Z:here's a wide-string" i:420 s:69
EAAAAG15IGZpcnN0IHN0cmluZwAqAAAAaABlAHIAZQAnAHMAIABhACAAdwBpAGQAZQAtAHMAdAByAGkAbgBnAAAApAEAAEUA
```

# Credits

CS2BR didn't invent (most of) the concepts it uses. It utilizes code from the following sources:

* [COFF Loader](https://github.com/trustedsec/COFFLoader) by trustedsec: Basis for the compatibility-layer and [encode_args.py](encode_args.py) script
* [Base64 C implementation](https://nachtimwald.com/2017/11/18/base64-encode-and-decode-in-c/) by John Schember: Basis for the compatibility-layer's base64 decoding

# See also

* Brute Ratel's [coffexec documentation](https://bruteratel.com/tabs/badger/commands/coffexec/)
* Cobalt Strike's [BOF documentation](https://hstechdocs.helpsystems.com/manuals/cobaltstrike/current/userguide/content/topics/beacon-object-files_main.htm)