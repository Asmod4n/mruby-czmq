module ZMQ
  class Pollitem
    def readable?
      (revents & POLLIN) != 0
    end

    def writable?
      (revents & POLLOUT) != 0
    end

    def error?
      (revents & POLLERR) != 0
    end

    if const_defined?(:POLLPRI)
      def priority?
        (revents & POLLPRI) != 0
      end
    end
  end
end
