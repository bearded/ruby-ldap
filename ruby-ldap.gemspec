require 'rubygems'

Gem::Specification.new do |s|
  s.platform = Gem::Platform::RUBY
  s.name = 'ruby-ldap'
  s.version = "0.9.9"
  s.summary = 'Ruby/LDAP is an extension module for Ruby'
  s.description = <<-EOF
It provides the interface to some LDAP libraries (e.g. OpenLDAP, Netscape SDK and Active Directory). The common API for application development is described in RFC1823 and is supported by Ruby/LDAP.
  EOF
  s.author = 'Alexey Chebotar'
  s.email = 'alexey.chebotar@gmail.com'
  s.rubyforge_project = 'ruby-ldap'
  s.homepage = 'http://ruby-ldap.sourceforge.net/'

  s.has_rdoc = true
  
  s.require_path = 'lib'

  s.files = [ 'ChangeLog', 'COPYING', 'FAQ', 'NOTES', 'README', 'TODO' ]
  s.files += Dir.glob('**/*.rb')
  s.files += Dir.glob('**/*.h')
  s.files += Dir.glob('**/*.c')

  s.extensions = ['extconf.rb']
end
