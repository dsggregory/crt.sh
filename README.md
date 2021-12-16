# A crt.sh Utility
This utility connects to the [crt.sh](https://crt.sh) database instead of their API which only supports minimal query types that return non-html (e.g. JSON).

Can query crt.sh for domains, fingerprints (SHA1 and SHA256), and Subject Key Identifiers. Output is a list of matching certificate elements, text as from `openssl x509 -text`, or JSON.

## Usage
```shell
go run main.go [opts] <query>
  -t string
        type of the query param - [domain, fingerprint, SKID]. Required for SKID query and optional for others
  -o string
        specifies the output format - [list, text, JSON] (default "list")
```

__Example__:
> go run main.go -t skid ec73502092a4656a6c9e0740362af4c483b7e4bd


## References
* https://crt.sh
* https://groups.google.com/g/crtsh/c/sUmV0mBz8bQ - use the DB instead
* https://github.com/crtsh/certwatch_db/blob/1c29538b838ea06d83271b0e3ef863c7d012b4b4/fnc/web_apis.fnc - helpful SQL provided by the certwatch module