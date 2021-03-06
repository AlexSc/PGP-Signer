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

helpers do
   def do_mail(options)
      body = TMail::Mail.new
      body.body = options[:body] || ""
      body.content_type = options[:body_content_type] || "text/plain"

      body
   end

   def show_error(url, log_items=[])
      log_items = [log_items].flatten
      log_items.each { |item| $stderr.puts item }
      redirect url
   end
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
         $iter = 0
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
      show_error('/badsignurl.html', 'Failed to verify')
   end

   show_error('/badsignurl.html', 'bad sig') unless GPGME::gpgme_err_code(signatures.first.status) == GPGME::GPG_ERR_NO_ERROR

   show_error('/badsignurl.html', 'Hello Mallory') unless signatures.first.fpr.downcase == options.our_fpr

   fpr = id.split($/)[3]
   keys = ctx.keys(fpr)

   show_error('/nokey.html') unless keys.first

   @keytext = GPGME.export(fpr, :armor => true)
   uid = keys.first.uids.first
   @name = uid.name
   @email = uid.email
   # HACK
   # Don't delete our key when running tests, it conflicts with the decryption
   # context used by the test.
   ctx.delete_key keys.first unless options.environment == :test

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

   show_error('/importerror.html') unless keys

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

get '/spoof' do
   erb :spoof
end

def valid_email?(email)
begin
   r = TMail::Address.parse(email)
   return true
rescue SyntaxError
   return nil
end
end

post '/spoof' do
   ctx = GPGME::Ctx.new(:armor=>true, :keylist_mode=>GPGME::KEYLIST_MODE_SIGS)
   keys, fpr = importKey ctx, params[:public_key]

   show_error('/importerror.html') unless keys

   wesigned = nil
   keys.first.uids.first.signatures.each do |signature|
      if options.our_fpr =~ /#{signature.keyid.downcase}$/
         wesigned = true
         break
      end
   end

   show_error('/spoofneedsign.html') unless wesigned

   begin
      ctx.verify(GPGME::Data.from_str(params[:signed_email]), nil)
      signatures = ctx.verify_result.signatures
      signatures.first.status
   rescue
      show_error('/spoofbadsign.html', 'Failed to verify')
   end

   show_error('/spoofbadsign.html') unless GPGME::gpgme_err_code(signatures.first.status) == GPGME::GPG_ERR_NO_ERROR

   show_error('/spoofwrongsign.html') unless signatures.first.fpr.downcase == fpr.downcase

   email = params[:signed_email].split($/)[3]
   email.strip!
   show_error('/spoofbademail.html') unless valid_email? email and email['@']
   @from_email = email
   @to_email = keys.first.uids.first.email

   Pony.mail(:to=>@to_email, :from=>@from_email, :subject=>'Example Spoof', :body=>erb(:spoofemail))

   erb :spoofsent
end
