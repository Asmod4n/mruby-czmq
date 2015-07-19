# mruby-czmq

Prerequirements
===============
You need to have czmq installed on your system, build and installation instructions: https://github.com/zeromq/czmq#building-and-installing

Examples
========

```ruby
server = CZMQ::Zsock.new ZMQ::ROUTER
server.bind "inproc://#{server.object_id}"

client = CZMQ::Zsock.new ZMQ::DEALER
client.identity = "client"
client.connect "inproc://#{server.object_id}"

client.sendx "", "hello world"

reactor = CZMQ::Reactor.new
reactor.timer(500, 5) do |timer|
  server.sendx(client.identity, '', 'test')
end

server_pi = reactor.poller(server) do |server_pi|
  server_pi.socket.sendx(*server_pi.socket.recvx)
end

client_pi = reactor.poller(client) do |client_pi|
  puts client_pi.socket.recvx.map(&:to_str)
end

reactor.run

```
