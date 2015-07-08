module CZMQ
  class Reactor
    class Timer
      attr_reader :when

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

      def call
        @block.call(self)
        if @times > 0 && (@times -= 1) == 0
          @reactor.timer_end(self)
        else
          @when += @delay
        end
      end
    end

    attr_accessor :interrupted

    def initialize
      @poller = Zpoller.new
      @timers = []
      @readers = {}
      @interrupted = false
    end

    def ignore_interrupts
      @poller.ignore_interrupts
    end

    def reader(socket, &block)
      raise ArgumentError, "no block given" unless block_given?
      if @readers.has_key?(socket)
        raise ArgumentError, "each sock can only be polled once"
      end
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
      @timers.sort!
      timer
    end

    def timer_end(timer)
      @timers.delete(timer)
      @timers.sort!
      self
    end

    def tickless
      tickless = Zclock.mono + 1000
      unless @timers.empty?
        tickless = @timers[0].when
      end
      timeout = tickless - Zclock.mono
      timeout < 0 ? 0 : timeout
    end

    def run
      until @poller.terminated? ||@interrupted
        if @timers.empty? && @readers.empty?
          break
        end
        if socket = @poller.wait(tickless)
          @readers[socket].call(socket)
        end
        now = Zclock.mono
        @timers.select {|timer| now >= timer.when}.map(&:call)
      end
      self
    end

    def run_once
      if socket = @poller.wait(tickless)
        @readers[socket].call(socket)
      end
      now = Zclock.mono
      @timers.select {|timer| now >= timer.when}.map(&:call)
      self
    end
  end
end
