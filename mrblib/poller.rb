module ZMQ
  class Poller
    def initialize
      @sockets = {}
    end

    def add(socket, events = POLLIN)
      pollitem = Pollitem.new(socket, events)
      @sockets[pollitem] = socket
      pollitem
    end

    alias :<< :add

    def remove(socket)
      @sockets.delete_if {|k, v| v == socket}
      self
    end

    def wait(timeout = -1)
      rc = ZMQ.poll(@sockets.keys, timeout)
      if rc.respond_to? :map!
        rc.map! {|poller| @sockets[poller]}
      else
        rc
      end
    end
  end
end
