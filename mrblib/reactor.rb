module CZMQ
  class Reactor
    class Timer
      include Comparable
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
        @when = Zclock.mono + @delay
      end

      def <=>(other)
        @when <=> other.when
      end

      def delay=(delay)
        delay = Integer(delay)
        raise ArgumentError, "delay must be 0 or greater" if delay < 0
        @delay = delay
        @when = Zclock.mono + @delay
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
        @delay = @reactor.ticket_delay
        @when = Zclock.mono + @delay
      end

      def reset
        @reactor.reset_ticket(self)
      end

      def call
        @block.call(self)
      end
    end

    attr_reader :ticket_delay
    attr_accessor :interrupted

    def initialize
      @poller = Zpoller.new
      @timers = []
      @tickets = []
      @readers = {}
      @ticket_delay = nil
      @interrupted = false
    end

    def ticket_delay=(delay)
      raise ArgumentError, "ticket delay cannot be changed" if @ticket_delay
      delay = Integer(delay)
      raise ArgumentError, "delay must be 0 or greater" if delay < 0
      @ticket_delay = delay
    end

    def ignore_interrupts
      @poller.ignore_interrupts
      self
    end

    def reader(socket, &block)
      if @readers.has_key?(socket)
        raise ArgumentError, "each sock can only be polled once"
      end
      raise ArgumentError, "no block given" unless block_given?
      @poller.add(socket)
      @readers[socket] = block
      self
    end

    def reader_end(socket)
      @poller.remove socket
      @readers.delete socket
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
      ticket = @tickets.delete_at(@tickets.index(ticket))
      ticket.when = Zclock.mono + @ticket_delay
      @tickets << ticket
      ticket
    end

    def ticket_delete(ticket)
      @tickets.delete_at(@tickets.index(ticket))
      self
    end

    def tickless
      tickless = Zclock.mono + 1000
      unless @timers.empty?
        tickless = @timers.min.when
      end
      if (ticket = @tickets.first)
        tickless = ticket.when
      end
      timeout = tickless - Zclock.mono
      timeout < 0 ? 0 : timeout
    end

    def run
      until @poller.terminated? ||@interrupted
        if @timers.empty? && @readers.empty?
          break
        end
        if (socket = @poller.wait(tickless))
          @readers[socket].call(socket)
        end
        now = Zclock.mono
        @timers.select {|timer| now >= timer.when}.each {|timer| timer.call}
        @tickets.delete_if {|ticket| now >= ticket.when}.each {|ticket| ticket.call}
      end
      self
    end

    def run_once
      if @timers.empty? && @readers.empty?
        return self
      end
      if (socket = @poller.wait(tickless))
        @readers[socket].call(socket)
      end
      now = Zclock.mono
      @timers.select {|timer| now >= timer.when}.each {|timer| timer.call}
      @tickets.delete_if {|ticket| now >= ticket.when}.each {|ticket| ticket.call}
      self
    end

    def run_nowait
      if @timers.empty? && @readers.empty?
        return self
      end
      if (socket = @poller.wait(0))
        @readers[socket].call(socket)
      end
      now = Zclock.mono
      @timers.select {|timer| now >= timer.when}.each {|timer| timer.call}
      @tickets.delete_if {|ticket| now >= ticket.when}.each {|ticket| ticket.call}
      self
    end
  end
end
