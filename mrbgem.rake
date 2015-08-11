MRuby::Gem::Specification.new('mruby-czmq') do |spec|
  spec.license = 'Apache-2'
  spec.author  = 'Hendrik Beskow'
  spec.summary = 'mruby bindings for czmq'
  spec.linker.libraries << 'czmq' << 'zmq'
  spec.add_dependency 'mruby-errno'
  spec.add_dependency 'mruby-msgpack', github: 'Asmod4n/mruby-simplemsgpack'
end
