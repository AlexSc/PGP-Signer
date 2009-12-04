require 'stringio'
require 'base64'
require 'cgi'

require 'rubygems'
require 'gpgme'
require 'sinatra'
require 'pony'
require 'tmail'

set :static, true

configure :production do
   set :our_fpr, 'B1B24106DB3F0D7CD7814E3C6DFDB4FC99D24387'.downcase
end

configure :test, :development do
   set :our_fpr, '1695901522B98B998278E01E845697D4E39D32D6'.downcase
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
   id = Base64.decode64(params[:id].gsub(' ', '+'))
   ctx = GPGME::Ctx.new
   begin
      ctx.verify(GPGME::Data.from_str(id), nil)
      signatures = ctx.verify_result.signatures
      signatures.first.status
   rescue
      $stderr.puts 'Failed to verify'
      redirect '/badsignurl.html'
   end

   unless GPGME::gpgme_err_code(signatures.first.status) == GPGME::GPG_ERR_NO_ERROR
      $stderr.puts 'bad sig'
      redirect '/badsignurl.html'
   end

   unless signatures.first.fpr.downcase == options.our_fpr
      $stderr.puts 'someone else signed this'
      redirect '/badsignurl.html'
   end

   fpr = id.split($/)[3]
   keys = ctx.keys(fpr)
   if keys.empty?
      redirect '/nokey.html'
   end
   @keytext = GPGME.export(fpr, :armor => true)
   uid = keys.first.uids.first
   @name = uid.name
   @email = uid.email
   ctx.delete_key keys.first

   mail = TMail::Mail.new()

   mail.to = @email
   mail.from = 'signer@pgpsigner.com'
   mail.subject = 'Signed PGP Key'

   mail.content_type = 'multipart/signed; boundary="mimepart_4b15e3947b281_17ff596e84e136"; 
   micalg=pgp-sha1; protocol="application/pgp-signature";'
   mail.disposition = 'inline'

   email_body = do_mail(:body=>(erb :signed_key))
   mail.parts.push email_body

   sig_attach = TMail::Mail.new
   real_mail = ''
   email_body.to_s.split($/).each do |line|
      line.strip!
      line += "\r\n"
      real_mail += line
   end
   signature = GPGME.detach_sign(GPGME::Data.from_str(real_mail.to_s), {:armor=>true})
   sig_attach.body = signature
   sig_attach.content_type = 'application/pgp-signature'
   sig_attach.set_content_disposition 'inline', 'name'=>'sig.asc'
   mail.parts.push sig_attach

   Pony.transport mail

   erb :signed_key_sent
end

get '/thanks_for_signing' do
   erb :thanks_for_signing
end

def rand_str(len)
   Array.new(len/2) { rand(256) }.pack('C*').unpack('H*').first
end

get '/public_key' do
   '<pre>' + GPGME.export(options.our_fpr, :armor=>true) + '</pre>'
end

def importKey(ctx, key)
   ctx.import(GPGME::Data.from_str(key))
   import_result = ctx.import_result
   unless import_result.imports.first
      return nil, nil
   end
   fpr = import_result.imports.first.fpr
   keys = ctx.keys(fpr)
   unless keys.first
      return nil, nil
   end
   return keys, fpr
end

post '/new' do
   data = params[:public_key]

   ctx = GPGME::Ctx.new({:armor=>true})
   keys, fpr = importKey(ctx, data)

   unless keys
      redirect '/importerror.html'
   end

   if fpr.downcase == options.our_fpr
      redirect '/thanks_for_signing'
   end

   ctx.edit_key(keys.first, method(:editfunc))

   url = GPGME.clearsign(GPGME::Data.from_str(fpr + "\n" + rand_str(80)), :armor=>true)
   url = CGI.escape Base64.encode64(url)

   uid = keys.first.uids.first
   @user_name = uid.name
   @user_email = uid.email
   @sign_url = url
   email_encrypted = GPGME.encrypt([keys.first], erb(:confirm_email), :armor=>true, :sign=>true)

   Pony.mail(:to=>uid.email, :from=>'signer@pgpsigner.com', :subject=>'Confirm PGP Key', :body=>email_encrypted)

   erb :mail_sent
end
