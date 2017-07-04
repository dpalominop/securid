Gem::Specification.new do |s|
  s.name = "securid"
  s.version = "0.2.7"

  s.authors = ["Ian Lesperance", "Edward Holets", "Daniel Palomino"]
  s.date = "2017-07-03"
  s.description = "A library for authenticating with an RSA SecurID ACE Authentication Server. Supports synchronous authenttication with ACE Server 6.1 and greater. Supports interactive and non-interactive flows."
  s.email = "dapalominop@gmail.com"
  s.extensions = ["ext/securid/extconf.rb"]
  s.files = ["ext/securid/securid.c", "ext/securid/securid.h", "ext/securid/extconf.rb", "lib/securid.rb", "README.md", "MIT-LICENSE"]
  s.require_paths = ["lib","/var/ace/RSA_AuthSDK/include","/var/ace/RSA_AuthSDK/lib/64bit/lnx/Release"]
  s.summary = "A library for authenticating with an RSA SecurID ACE Authentication Server"
  s.homepage = "https://github.com/dpalominop/securid"
  s.license = 'MIT'
  s.required_ruby_version = '>= 2.0.0'
end
