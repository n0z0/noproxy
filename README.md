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

## Method 1: The Classic Approach (Advanced Users) as Gateway

This method gives you the most control but requires manual configuration. The most famous tool for this is badvpn-tun2socks.

*Tools Needed:*

1. *TAP-Windows Driver:* The virtual network driver. The easiest way to get this is by installing [OpenVPN](https://openvpn.net/community-downloads/). During installation, make sure the "TAP-Windows6" component is selected.
2. *badvpn-tun2socks:* A lightweight, standalone executable that does the packet forwarding. You can download pre-compiled binaries from its GitHub releases page or other community sources.

*Step-by-Step Guide:*

*Step 1: Install and Configure the TAP Adapter*

1. Install OpenVPN to get the TAP driver.
2. Go to Control Panel > Network and Internet > Network and Sharing Center > Change adapter settings.
3. You should see an adapter named "TAP-Windows6 V9" or similar. Rename it to something simple, like mytap.
4. Right-click mytap > Properties.
5. Double-click Internet Protocol Version 4 (TCP/IPv4).
6. Set a static IP address and netmask. This will be the gateway for your tunneled traffic.
    * *IP address:* 10.0.0.1
    * *Subnet mask:* 255.255.255.0
    * Click OK.

*Step 2: Run tun2socks*
Open a Command Prompt or PowerShell as an administrator. Navigate to where you saved badvpn-tun2socks.exe.

The command structure is:

badvpn-tun2socks.exe --tundev "mytap" --netif-ipaddr 10.0.0.2 --netif-netmask 255.255.255.0 --socks-server-addr <PROXY_IP>:<PROXY_PORT>

* --tundev "mytap": The name of your TAP adapter.
* --netif-ipaddr 10.0.0.2: The IP address for the tun2socks application itself on the virtual network. It must be on the same subnet as the TAP adapter but different from its IP.
* --netif-netmask 255.255.255.0: The subnet mask, matching the TAP adapter.
* --socks-server-addr <PROXY_IP>:<PROXY_PORT>: The address of your SOCKS5 proxy server.

*Example:*
If your SOCKS5 proxy is at 192.168.1.100:1080, the command would be:

badvpn-tun2socks.exe --tundev "mytap" --netif-ipaddr 10.0.0.2 --netif-netmask 255.255.255.0 --socks-server-addr 192.168.1.100:1080

Leave this command prompt window running.

*Step 3: Configure Windows Routing*
This is the most critical step. You need to add routes that tell Windows to send traffic through the mytap interface.

1. *Find your main gateway:* Open Command Prompt and run ipconfig. Look for your primary Ethernet or Wi-Fi adapter and note its "Default Gateway" (e.g., 192.168.1.1).
2. *Find your proxy server's IP:* (e.g., 192.168.1.100).
3. *Add the routes:*

    cmd
    :: IMPORTANT: Route traffic to the proxy server DIRECTLY, not through the tunnel.
    :: This prevents a routing loop.
    route add <PROXY_IP> MASK 255.255.255.255 <YOUR_MAIN_GATEWAY>

    :: Route all other traffic through the TUN interface.
    :: The gateway here is the IP of the tun2socks app.
    route add 0.0.0.0 MASK 0.0.0.0 10.0.0.2 METRIC 1

    *Example:*
    cmd
    route add 192.168.1.100 MASK 255.255.255.255 192.168.1.1
    route add 0.0.0.0 MASK 0.0.0.0 10.0.0.2 METRIC 1

Now, all your traffic (except traffic to the proxy itself) will be routed through tun2socks and to your proxy server.

*To remove the routes later:*
cmd
route delete <PROXY_IP>
route delete 0.0.0.0

## RELEASE

```sh
git tag v0.0.1
git push origin --tags
go list -m github.com/n0z0/noproxy@v0.0.1
```
