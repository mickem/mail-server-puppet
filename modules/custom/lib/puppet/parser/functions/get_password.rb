module Puppet::Parser::Functions
  newfunction(:get_password, :type => :rvalue, :doc => <<-EOS
    EOS
  ) do |arguments|
    raise(Puppet::ParseError, "get_password(): Wrong number of arguments " +
      "given (#{arguments.size} for 2)") if arguments.size < 1

    filename = arguments[0]

	unless filename.is_a? String
		raise Puppet::ParseError "get_password(): expected first argument to be a String, got #{filename.inspect}"
	end
	
	length = 12
	if arguments.size > 1
		length = arguments[1].to_i
	end

	if FileTest.exists?(filename)
		parser = Puppet::Parser::Parser.new(environment)
		parser.watch_file(filename)
		return IO.readlines(filename).join("").strip
	else
		specials = ((33..33).to_a + (35..36).to_a).pack('U*').chars.to_a
		numbers  = (0..9).to_a
		alphal = ('a'..'z').to_a
		alphau = ('A'..'Z').to_a
		CHARS = (alphal + numbers + alphau + alphal + numbers + alphau)
		pwd = CHARS.sort_by { rand }.join[0...length]
		IO.write(filename, pwd)
		return pwd		
	end
  end
end