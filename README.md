# Client-Proxy-Server two-way communication via RAW sockets

<p>
<a href="#"><img alt="C++" src = "https://img.shields.io/badge/C%2B%2B%2017-black.svg?style=for-the-badge&logo=cplusplus&logoColor=white"></a>
<a href="#"><img alt="CMake" src="https://img.shields.io/badge/Make-black?style=for-the-badge&logo=gnu&logoColor=white"></a>
</p>

<h3>Workflow:</h3>
<p>
<ul>
<li>Server launches and listens for connection request</li>
  
<li>Proxy establishes connection with server via TCP-handshake</li>

<li>Client establishes connection with proxy via TCP-handshake </li>

<li>Client send packet to server (through proxy)</li>

<li>Proxy changes packet payload with 50% chance</li>

<li>Server receives packet and sends response</li>

<li>Proxy captures response and forwards to client</li>

<li>Both receiving ends recalculate checksum and parse packet contents</li>
</ul>
</p>

<h3>usage:</h3>

```bash
> git clone https://github.com/webmessia-h/tcpClientServerGUI/tree/main

> cd clientProxyServer

> make

#! run everything with SUDO privileges, they're revoked after socket creation
> ./server_exec <server_ip> <server_port>

> ./proxy_exec <proxy_ip> <proxy_port>  <server_ip> <server_port>

> ./client_exec <client-ip>  <proxy_ip> <proxy_port>
```
