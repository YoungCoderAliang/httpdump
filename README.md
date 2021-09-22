# httpdump
**a simple tool for dump http packets**, you may use it to detect and protect your sensitive data in a production environment especially read flow from switch.

it supports simple http network flow in http1.0/http1.1.

it does **not support https/http2/chunked http response** , maybe i will support them in a few days but who knows ...

this is a first go project for me, so maybe it's not such graceful, if you have better way to code please tell me.



the way to use it :

`httpChan := httpdump.DumpIf(ifName)`

you may like to have an **example** in [test_dump.go](https://github.com/YoungCoderAliang/httpdump/blob/main/test_dump.go)



if you have any good idea just let me know

email:  78407033@qq.com

I do will check them at least once a year
