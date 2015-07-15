module CZMQ
  class Zsock
    def to_pollitem(events = ZMQ::POLLIN)
      ZMQ::Pollitem.new(self, 0, events)
    end
  end
end
