# mruby-czmq

Examples
========

```ruby
server = CZMQ::Zsock.new ZMQ::ROUTER
server.bind "inproc://#{server.object_id}"

client = CZMQ::Zsock.new ZMQ::DEALER
client.connect "inproc://#{server.object_id}"

client.sendx "", "hello world"

reactor = CZMQ::Reactor.new

server_pi = reactor.poller(server) do |server_pi|
  id, _, msg = server_pi.socket.recvx
  server_pi.socket.sendx(id, msg)
end

client_pi = reactor.poller(client) do |client_pi|
  puts client_pi.socket.recvx.map(&:to_str)
end

reactor.run

```
