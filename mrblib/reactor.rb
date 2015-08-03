module CZMQ
  class Reactor
    class Timer
      attr_reader :delay, :times, :when

      def initialize(reactor, delay, times, &block)
        delay = Integer(delay)
        raise ArgumentError, "delay must be 0 or greater" if delay < 0
        times = Integer(times)
        raise ArgumentError, "times must be 0 or greater" if times < 0
        raise ArgumentError, "no block given" unless block_given?
        @reactor = reactor
        @delay = delay
        @times = times
        @block = block
        @when = Zclock.mono + delay
      end

      def <=>(other)
        @when <=> other.when
      end

      def delay=(delay)
        delay = Integer(delay)
        raise ArgumentError, "delay must be 0 or greater" if delay < 0
        @delay = delay
        @when = Zclock.mono + delay
      end

      def times=(times)
        times = Integer(times)
        raise ArgumentError, "times must be 0 or greater" if times < 0
        @times = times
      end

      def call
        @block.call(self)
        if @times > 0 && (@times -= 1) == 0
          @reactor.timer_end(self)
        else
          @when += @delay
        end
      end
    end

    class Ticket
      attr_accessor :when

      def initialize(reactor, &block)
        raise ArgumentError, "no block given" unless block_given?
        @reactor = reactor
        @block = block
        @when = Zclock.mono + reactor.ticket_delay
      end

      def reset
        @reactor.ticket_reset(self)
      end

      def call
        @block.call(self)
        @reactor.ticket_delete(self)
      end
    end

    attr_reader :ticket_delay
    attr_accessor :interrupted

    def initialize
      @poller = ZMQ::Poller.new
      @pollers = {}
      @timers = []
      @tickets = []
      @interrupted = false
      @ticket_delay = nil
    end

    def ticket_delay=(delay)
      raise ArgumentError, "ticket delay cannot be changed" if @ticket_delay
      delay = Integer(delay)
      raise ArgumentError, "delay must be 0 or greater" if delay < 0
      @ticket_delay = delay
    end

    def poller(socket, events = ZMQ::POLLIN, &block)
      raise ArgumentError, "no block given" unless block_given?
      pollitem = @poller.add(socket, events)
      @pollers[pollitem] = block
      pollitem
    end

    def poller_end(socket)
      @poller.remove socket
      @pollers.delete_if {|pollitem, _| pollitem.socket == socket}
      self
    end

    def timer(delay, times, &block)
      timer = Timer.new(self, delay, times, &block)
      @timers << timer
      timer
    end

    def timer_end(timer)
      @timers.delete(timer)
      self
    end

    def ticket(&block)
      raise ArgumentError, "ticket_delay must be set" unless @ticket_delay
      ticket = Ticket.new(self, &block)
      @tickets << ticket
      ticket
    end

    def ticket_reset(ticket)
      ticket = @tickets.delete_at(@tickets.rindex(ticket))
      @tickets << ticket
      ticket.when = Zclock.mono + @ticket_delay
      self
    end

    def ticket_delete(ticket)
      @tickets.delete_at(@tickets.index(ticket))
      self
    end

    def run
      until Zsys.interrupted?||@interrupted
        if @pollers.empty? && @timers.empty? && @tickets.empty?
          return false
        end
        if (pollitems = @poller.wait(tickless))
        if pollitems.respond_to?(:each)
          pollitems.each {|pollitem| @pollers[pollitem].call(pollitem)}
        else
          @pollers[pollitems].call(pollitems)
        end
        end
        now = Zclock.mono
        @timers.select {|timer| now >= timer.when}.each {|timer| timer.call}
        @tickets.take_while {|ticket| now >= ticket.when}.each {|ticket| ticket.call}
      end
      self
    end

    def run_once
      if @pollers.empty? && @timers.empty? && @tickets.empty?
        return false
      end
      if (pollitems = @poller.wait(tickless))
        if pollitems.respond_to?(:each)
          pollitems.each {|pollitem| @pollers[pollitem].call(pollitem)}
        else
          @pollers[pollitems].call(pollitems)
        end
      end
      now = Zclock.mono
      @timers.select {|timer| now >= timer.when}.each {|timer| timer.call}
      @tickets.take_while {|ticket| now >= ticket.when}.each {|ticket| ticket.call}
      self
    end

    def run_nowait
      if @pollers.empty? && @timers.empty? && @tickets.empty?
        return false
      end
      if (pollitems = @poller.wait(0))
        if pollitems.respond_to?(:each)
          pollitems.each {|pollitem| @pollers[pollitem].call(pollitem)}
        else
          @pollers[pollitems].call(pollitems)
        end
      end
      now = Zclock.mono
      @timers.select {|timer| now >= timer.when}.each {|timer| timer.call}
      @tickets.take_while {|ticket| now >= ticket.when}.each {|ticket| ticket.call}
      self
    end

    private
    def tickless
      wann = Zclock.mono + 1000
      unless @timers.empty?
        wann = @timers.min.when
      end
      if (ticket = @tickets.first)
        wann = ticket.when
      end
      tickless = wann - Zclock.mono
      tickless < 0 ? 0 : tickless
    end
  end
end
