module CZMQ
  class Zsock
    def to_pollitem(events = ZMQ::POLLIN)
      ZMQ::Pollitem.new(self, events)
    end
  end
end
