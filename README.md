# Session Cookies and Data

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