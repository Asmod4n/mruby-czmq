module CZMQ
  class Reactor
    Timer = Struct.new(:delay, :times, :callback)
    def initialize
      @timers = []
      @readers = {}
      @poller = Zpoller.new
      @needs_rebuild = false
    end

    def reader(socket, &block)
      raise ArgumentError, "no block given" unless block_given?
      @poller.add(socket)
      @readers[socket] = block
      self
    end

    def reader_end(socket)
      raise ArgumentError, "no poller started" unless @poller
      @poller.remove socket
      @readers.delete socket
      self
    end

    def timer(delay, times, &block)
      raise ArgumentError, "no block given" unless block_given?
      delay = Integer(delay)
      times = Integer(times)
      timer = Timer.new(delay, times, block)
      @timers << timer
      @needs_rebuild = true
      timer
    end

    def timer_end(timer)
      @timers.delete(timer)
      @needs_rebuild = true
      self
    end

    def start
      until Zsys.interrupted?
        res = nil
        if @timers.empty? && @readers.empty?
          break
        end
        if @needs_rebuild
          @timers.sort! {|x, y| x.delay <=> y.delay}
          @needs_rebuild = false
        end
        now = Zclock.mono
        if @timers.empty?
          res = @poller.wait
        else
          res = @poller.wait @timers.first.delay
        end
        if res
          @readers[res].call(res)
        end
        @timers.select {|timer| timer.delay <= (Zclock.mono - now)}.each {|timer| timer.callback.call(timer)}
      end
    end
  end
end
