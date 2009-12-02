require 'stringio'
require 'base64'
require 'cgi'

require 'gpgme'

require 'rubygems'
require 'sinatra'
require 'openpgp'
require 'pony'
require 'tmail'

set :static, true

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
	id = Base64.decode64(params[:id])
   uid = ''
	GPGME.verify(GPGME::Data.from_str id, nil) do |output|
      if GPGME::gpgme_err_code(output.status) == GPGME::GPG_ERR_NO_ERROR
      	validkey = true
         uid_raw = id.split($/)[3]
         case uid_raw
            # User IDs of the form: "name (comment) <email>"
            when /^([^\(]+)\(([^\)]+)\)\s+<([^>]+)>$/
               @name, @comment, @email = $1, $2, $3
            # User IDs of the form: "name <email>"
            when /^([^<]+)\s+<([^>]+)>$/
               @name, @comment, @email = $1, nil, $2
            # User IDs of the form: "name"
            when /^([^<]+)$/
               @name, @comment, @email = $1, nil, nil
            # User IDs of the form: "<email>"
            when /^<([^>]+)>$/
               @name, @comment, @email = nil, nil, $2
            else
               @name, @comment, @email = nil
           end
         ctx = GPGME::Ctx.new
   		keys = ctx.keys(uid_raw)
         if keys.empty?
            break
         else
            havekey = true
      	   keydata = GPGME.export(uid_raw, :armor => true)
            @keytext = keydata
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
   mail.from = 'ps@test.com'
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
   
   'Your key has been signed and sent to ' + @email
   
end

post '/new' do
	data = params[:public_key]
   strFile = StringIO.new(data, 'r')
   
   uid = ''
   
   msg = OpenPGP::Message.parse OpenPGP.dearmor(data)
   msg.each do |packet|
   	if packet.tag == 13
      	uid = packet
         break
      end
   end
   
   GPGME.import strFile
   ctx = GPGME::Ctx.new({:armor=>true})
   keys = ctx.keys(uid.data)
   if keys.empty?
   	return 'Err... what?'
   end
   ctx.edit_key(keys.first, method(:editfunc))
   
   url = GPGME.clearsign(GPGME::Data.from_str uid.data, 
                    :armor=>true)
   url = CGI.escape Base64.encode64(url)
   
   @user_name = uid.name
   @sign_url = url
   
   email_plain = erb :confirm_email
   email_encrypted = GPGME.encrypt([keys.first], email_plain, :armor=>true, :sign=>true)
   Pony.mail(:to=>uid.email, :from=>'ps@test.com', :subject=>'Confirm PGP Key', :body=>email_encrypted)
   
   'An encrypted email has been sent to ' + uid.email + ', decrypt it and click on the enclosed link to get your signed key'
   
end
