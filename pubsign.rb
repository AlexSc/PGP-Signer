require 'stringio'
require 'base64'
require 'cgi'

require 'rubygems'
require 'gpgme'
require 'sinatra'
require 'pony'
require 'tmail'

set :static, true

our_fpr = 'B1B24106DB3F0D7CD7814E3C6DFDB4FC99D24387'.downcase

def save_our_key
   keydata = GPGME.export(our_fpr, :armor=>true)
   File.open('public/public_service.asc', 'w') { |file|
   	file << keydata
   }
end

configure :production do
	save_our_key
end

def do_mail(options)
	body = TMail::Mail.new
   body.body = options[:body] || ""
   body.content_type = options[:body_content_type] || "text/plain"
   
   body
end
   
$iter = 0
def editfunc(hook, status, args, fd)
  case status
  when GPGME::GPGME_STATUS_GET_BOOL
    io = IO.for_fd(fd)
    io.puts('y\n')
    io.flush
  when GPGME::GPGME_STATUS_GET_LINE, GPGME::GPGME_STATUS_GET_HIDDEN
    line = ''
    if $iter == 0
      line = 'sign'
      $iter += 1
    elsif $iter == 1
      line = 'quit'
      $iter = 0;
    end
    io = IO.for_fd(fd)
    io.puts(line)
    io.flush
  else
  end
end


get '/' do
	erb :index
end

get '/new' do
	erb :new
end

get '/sign/:id' do
	havekey = false
   validkey = false
   escaped_id = params[:id]
   escaped_id.gsub! ' ', '+'
	id = Base64.decode64(escaped_id)
   uid = ''
	GPGME.verify(GPGME::Data.from_str(id), nil) do |output|
      if GPGME::gpgme_err_code(output.status) == GPGME::GPG_ERR_NO_ERROR
      	validkey = true
         fpr = id.split($/)[3]
         ctx = GPGME::Ctx.new
   		keys = ctx.keys(fpr)
         if keys.empty?
            break
         else
            havekey = true
      	   keydata = GPGME.export(fpr, :armor => true)
            @keytext = keydata
            uid = keys.first.uids.first
            @name = uid.name
            @email = uid.email
            ctx.delete_key keys.first
   		   break
         end
      else
      	break
      end
   end
   
   if !havekey
   	return "It looks like we don't have your key, maybe you've already had it signed?"
   end
   
   email_plain = erb :signed_key
   email_body = do_mail(:body=>email_plain)
   email_list = email_body.to_s.split($/)
   real_mail = ''
   email_list.each do |line|
   	line.strip!
      line += "\r\n"
      real_mail += line
   end
   
   signature = GPGME.detach_sign(GPGME::Data.from_str(real_mail.to_s), {:armor=>true})
   
   mail = TMail::Mail.new()
   
   mail.to = @email
   mail.from = 'signer@pgpsigner.com'
   mail.subject = 'Signed PGP Key'
   
   mail.content_type = 'multipart/signed; boundary="mimepart_4b15e3947b281_17ff596e84e136"; 
   micalg=pgp-sha1; protocol="application/pgp-signature";'
   mail.disposition = 'inline'
   mail.parts.push email_body
   
   sig_attach = TMail::Mail.new
   sig_attach.body = signature
   sig_attach.content_type = 'application/pgp-signature'
   sig_attach.set_content_disposition 'inline', 'name'=>'sig.asc'
   
   mail.parts.push sig_attach
   
   Pony.transport mail
   
   erb :signed_key_sent
   
end

get '/importerror' do
	erb :importerror
end

our_fpr = 'B1B24106DB3F0D7CD7814E3C6DFDB4FC99D24387'.downcase

get '/thanks_for_signing' do
	save_our_key
	erb :thanks_for_signing
end

def rand_str(len)
  Array.new(len/2) { rand(256) }.pack('C*').unpack('H*').first
end

post '/new' do
	data = params[:public_key]
   
   ctx = GPGME::Ctx.new({:armor=>true})
   ctx.import(GPGME::Data.from_str(data))
   import_result = ctx.import_result
   unless import_result.imports.first
      $stderr.puts 'Failed to import the key'
      $stderr.puts data
   	redirect '/importerror'
   end
   fpr = import_result.imports.first.fpr
   
   if fpr.downcase == our_fpr
   	redirect '/thanks_for_signing'
   end
   
   keys = ctx.keys(fpr)
   if keys.empty?
   	$stderr.puts 'Failed to import the key'
      $stderr.puts data
   	redirect '/importerror'
   end
   ctx.edit_key(keys.first, method(:editfunc))
   
   uid = keys.first.uids.first
   
   rnd_str = rand_str 80
   unsigned_url = fpr + "\n" + rnd_str
   
   url = GPGME.clearsign(GPGME::Data.from_str unsigned_url, 
                    :armor=>true)
   url = CGI.escape Base64.encode64(url)
   
   @user_name = uid.name
   @user_email = uid.email
   @sign_url = url
   
   email_plain = erb :confirm_email
   email_encrypted = GPGME.encrypt([keys.first], email_plain, :armor=>true, :sign=>true)
   
   Pony.mail(:to=>uid.email, :from=>'signer@pgpsigner.com', :subject=>'Confirm PGP Key', :body=>email_encrypted)
   
   erb :mail_sent
end
