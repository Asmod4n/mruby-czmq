module ZMQ
  class Poller
    def initialize
      @pollitems = []
    end

    def add(socket, events = POLLIN)
      pollitem = Pollitem.new(socket, events)
      @pollitems << pollitem
      pollitem
    end

    alias :<< :add

    def remove(socket)
      @pollitems.delete_if {|pollitem| pollitem.socket == socket}
      self
    end

    def wait(timeout = -1)
      ZMQ.poll(@pollitems, timeout)
    end
  end
end
