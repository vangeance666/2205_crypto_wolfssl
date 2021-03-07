# Loading code up on Visual Studio
- Launch wolfssl.sln at root folder with Visual Studio. The codes are within *crypto* project.

# Structure
Files within in *crypto* project.

| Filename | Description |
| --- | --- |
| argparse.h | Contains function to parse user input from main and toggle different modes. |
| callback.h | Contains peer verification callback function to print peer certs details. |
| certfields.h | Contains all the helper functions which will be used for parsing PEM certs. Printing of public key information, cert fields & of public key’s N & E can be conducted using those functions. |
| common.h | Helper functions for conducting C stuffs. Strings comparison, copying and slicing, etc. |
| globals.h | Contains macros, definitions return codes, used throughout the whole program. |
| requests.h | Contains helper functions which utilizes wolfSSL_read and wolfSSL_write to interact with server/website using GET/POST messages. |
| verify.h | Contains all required functions which will be used for verifying peer certs. 
| main.c | Main program. (All procedures are here)  |


# Usage
1. On your windows command prompt, navigate to:
> Release/
2. A crypto.exe should have be compiled for you. You can build yourself if you want with VSS.
3. Execute it using command prompt. To view the help menu, type `crypto.exe -?`
<pre>
-v              Verify cert manual mode (using CertManager), please specify -C and -V certs.
-p [path]       Loads cert from [path] and display key details (With M & E inclusive)
-h [hostname]   Host to connect to, for e.g. youtube.com
-G [params]     Sends GET crafted message from params. For example sch=sit&name=luliming. Concat with '&' symbol.
-P [params]     Sends POST crafted message from params. For example sch=sit&name=luliming. Concat with '&' symbol.
-C [path]       CA cert file [path] to verify intermediate cert.
-V [path]       Intermediate cert file [path] to be verified by CA cert specified.
-s [path]       File path of where server's response using GET/POST will be saved into.
-a <request header> Additional request header, delimit using '&' E.g. "Connection: close&Content-Length: 0"
</pre>


# Examples

## Printing cert details
`➜ crypto.exe -p "youtube-server.pem"`

## Verify cert
`➜ crypto.exe -v -C "CA-Cert.pem" -V "cert-toverify.pem`

## Sending messages GET/POST via SSL
### Default (Requests for root path)
`➜ crypto.exe -h youtube.com -G` 

### Parameters usage
`➜ crypto.exe -h youtube.com/results -G search_query=ihate+school`

### Sending POST message via SSL
`➜ crypto.exe -h "www.allforyou.sg/login" -P "Email=test@test.com&Password=pass" -a "content-length: 0"

![Alt text](Screenshots/CA verify.jpg?raw=true "Title")
