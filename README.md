# Session Cookies and Data

Install Cert Root CA

```sh
certutil -addstore -f "ROOT" root-ca.crt
```

## Test

```txt
curl -k -v --proxy http://127.0.0.1:8080 https://httpbin.org/cookies/set/PHPSESSID/test123value
```

```sh
# Terminal 1: Proxy sudah running
# Terminal 2: Test URL-encoded POST
curl -X POST --proxy http://127.0.0.1:8080 \
     -H "Content-Type: application/x-www-form-urlencoded" \
     -d "username=john&password=secret123&csrf_token=abc123" \
     https://httpbin.org/post

# Terminal 3: Test JSON POST
curl -X POST --proxy http://127.0.0.1:8080 \
     -H "Content-Type: application/json" \
     -d '{"username":"john","password":"secret123","remember":true}' \
     https://httpbin.org/post
```

```sh
# URL-encoded form
curl -X POST -d "username=john&password=secret" --proxy http://127.0.0.1:8080 https://httpbin.org/post

# JSON form  
curl -X POST -H "Content-Type: application/json" -d '{"user":"john"}' --proxy http://127.0.0.1:8080 https://httpbin.org/post
```

## GZIP

```go
// Bungkus dengan bufio.Reader supaya bisa Peek tanpa menghabiskan data
		br := bufio.NewReader(req.Body)

		// Coba sniff 2 byte pertama (magic number gzip: 0x1f 0x8b)
		magic, err := br.Peek(2)
		isGzip := err == nil &&
			len(magic) == 2 &&
			magic[0] == 0x1f &&
			magic[1] == 0x8b

		var r io.Reader = br

		if isGzip {
			log.Println("====================GZIP DETECTED================")
			gz, err := gzip.NewReader(br)
			if err == nil {
				r = gz
				log.Println(r)
			}
			defer gz.Close()

		}

		// Kalau gzip → r = gz, kalau bukan → r = br
		bodyData, _ = io.ReadAll(r)
```

## RELEASE

```sh
git tag v0.0.1
git push origin --tags
go list -m github.com/n0z0/noproxy@v0.0.1
```
