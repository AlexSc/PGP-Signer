require 'pubsign'
require 'spec'
require 'rack/test'
require 'gpgme'
require 'base64'
require 'cgi'

our_fpr = '1695901522B98B998278E01E845697D4E39D32D6'.downcase

def gen_test_key()
   GPGME::Ctx.new do |ctx|
      ctx.genkey(<<'EOF', nil, nil)
      <GnupgKeyParms format="internal">
      Key-Type: DSA
      Key-Length: 1024
      Subkey-Type: ELG-E
      Subkey-Length: 1024
      Name-Real: TestKey
      Name-Email: test_email@pgpsigner.com
      Expire-Date: 0
      </GnupgKeyParms>
EOF
      ctx.armor=true
      keydata = ctx.export 'TestKey'
      keydata.seek(0, IO::SEEK_SET)
      File.open('testdata/test_pk.asc', 'w') { |file| file.syswrite keydata.read }
   end
end

def clear_test_key
   GPGME::Ctx.new do |ctx|
      pkeys = ctx.keys 'TestKey', true
      pkeys.each { |key| ctx.delete_key key, true }
      pkeys = ctx.keys 'TestKey'
      pkeys.each { |key| ctx.delete_key key, true }
   end
end

Spec::Runner.configure do |conf|
   conf.include Rack::Test::Methods
end

set :environment, :test

describe 'Key Submission' do
   before :all do
      gen_test_key
   end

   after :all do
      clear_test_key
   end

   def app
      Sinatra::Application
   end

   it 'Errors on failed import' do
      post '/new', :public_key=>''
      last_response.should be_redirect
      last_response.location.should include 'error'
   end

   it 'Imports with good key' do
      def Pony.transport(tmail)
         # Don't do anything
      end
      post '/new', 'public_key'=>IO.read('testdata/test_pk.asc')
      last_response.should be_ok
      last_response.body.should include 'test_email@pgpsigner.com'
   end

   it 'Should send email for good key' do
      $mailmessage = nil
      def Pony.transport(tmail)
         $mailmessage = tmail
      end
      post '/new', 'public_key'=>IO.read('testdata/test_pk.asc')
      $mailmessage.should_not be_nil
   end
	
   it 'Should be an encrypted email with a link' do
      $mailmessage = nil
      def Pony.transport(tmail)
         $mailmessage = tmail
      end
      post '/new', 'public_key'=>IO.read('testdata/test_pk.asc')
      GPGME::Ctx.new do |ctx|
         decrypted = ctx.decrypt_verify GPGME::Data.from_str($mailmessage.body) 
         decrypted.seek(0, IO::SEEK_SET)
         decrypted.read.should include 'http://www.pgpsigner.com/sign/'
         ctx.verify_result.signatures.first.fpr.downcase.should include our_fpr
      end
   end

   it 'Should recognize its own key' do
      post '/new', 'public_key'=>IO.read('testdata/pbsign_pk.asc')
      last_response.should be_redirect
      last_response.location.should include 'thanks'
   end
end

describe 'Public Key' do
   def app
      Sinatra::Application
   end

   it 'Should show the public key' do
      get '/public_key'
      last_response.should be_ok
      last_response.body.should include IO.read('testdata/pbsign_pk.asc')
   end
end

describe 'Key Signing' do
   before :all do
      gen_test_key
   end

   after :all do
      clear_test_key
   end

	def app
      Sinatra::Application
   end

   it 'Errors on invalid data' do
      get '/sign/sfdljk'
      last_response.should be_redirect
      last_response.location.should include 'badsign'
   end

   it 'Errors on invalid signature' do
      signed = GPGME.clearsign('Test', :signers=>['TestKey'])
      get '/sign/' + CGI.escape(Base64.encode64 signed)
      last_response.should be_redirect
      last_response.location.should include 'badsign'
   end

   it 'Errors on lack of key' do
      signed = GPGME.clearsign('does_not_exist', :signers=>['PubSign'])
      get '/sign/' + CGI.escape(Base64.encode64 signed)
      last_response.should be_redirect
      last_response.location.should include 'nokey'
   end

   it 'Succeeds with valid url' do
      $mailmessage = nil
      def Pony.transport(tmail)
         $mailmessage = tmail
      end
      post '/new', 'public_key'=>IO.read('testdata/test_pk.asc')
      ctx = GPGME::Ctx.new
      decrypted = ctx.decrypt GPGME::Data.from_str $mailmessage.body 
      decrypted.seek(0, IO::SEEK_SET)
      url = decrypted.read()[/\/sign\/.*\s/]
      get url
      
      last_response.should be_ok
      last_response.body.should include 'test_email@pgpsigner.com'
   end

   it 'Sends signed key with valid url' do
      $mailmessage = nil
      def Pony.transport(tmail)
         $mailmessage = tmail
      end
      post '/new', 'public_key'=>IO.read('testdata/test_pk.asc')
      ctx = GPGME::Ctx.new :armor=>true
      decrypted = ctx.decrypt GPGME::Data.from_str $mailmessage.body 
      decrypted.seek(0, IO::SEEK_SET)
      url = decrypted.read()[/\/sign\/.*\s/]
      get url

      $mailmessage.parts.length.should be 2
      real_mail = ''
      $mailmessage.parts[0].to_s.split($/).each do |line|
         line.strip!
         line += "\r\n"
         real_mail += line
      end

      signed_text = GPGME::Data.from_str real_mail
      sig = GPGME::Data.from_str $mailmessage.parts[1].body.to_s

      ctx.verify(sig, signed_text, nil)
      GPGME::gpgme_err_code(ctx.verify_result.signatures.first.status).should be GPGME::GPG_ERR_NO_ERROR

      clear_test_key

      ctx.import_keys GPGME::Data.from_str $mailmessage.body
      ctx.keylist_mode=GPGME::KEYLIST_MODE_SIGS
      key = ctx.keys ctx.import_result.imports.first.fpr
      wesigned = false
      key.first.uids.first.signatures.each do |signature|
         if our_fpr =~ /#{signature.keyid.downcase}$/
            wesigned = true
            break
         end
      end
      wesigned.should be_true
   end
end

describe 'Email Forgery' do
   before :all do
      gen_test_key
   end

   after :all do
      clear_test_key
   end

   def app
      Sinatra::Application
   end

   it 'Should fail with bad public key' do
      post '/spoof', 'public_key'=>'fsdkljjdsa'
      last_response.should be_redirect
      last_response.location.should include 'error'
   end

   it 'Should fail with an unsigned public key' do
      post '/spoof', 'public_key'=>IO.read('testdata/test_pk.asc')
      last_response.should be_redirect
      last_response.location.should include 'needsign'
   end

   def ensure_signed()
      # First make sure our public key is signed
      def Pony.transport(tmail)
      end
      post '/new', 'public_key'=>IO.read('testdata/test_pk.asc')

      # Save out the public key
      File.open('testdata/test_pk.asc', 'w') { |f| f.syswrite(GPGME.export('TestKey', :armor=>true)) }
   end

   it 'Should fail with an unsigned email' do
      ensure_signed

      post '/spoof', :public_key=>IO.read('testdata/test_pk.asc'), :signed_email=>'test_email@pgpsigner.com'
      last_response.should be_redirect
      last_response.location.should include 'badsign'
   end

   it 'Should fail if email was signed by different key' do
      ensure_signed

      sig = GPGME.sign('test_email@pgpsigner.com', :signers=>['PubTest'], :mode=>GPGME::SIG_MODE_CLEAR)
      post '/spoof', :public_key=>IO.read('testdata/test_pk.asc'), :signed_email=>sig

      last_response.should be_redirect
      last_response.location.should include 'wrongsign'
   end

   it 'Should fail if email is invalid' do
      ensure_signed

      sig = GPGME.sign('*(@!()*&&)(', :signers=>['TestKey'], :mode=>GPGME::SIG_MODE_CLEAR)
      post '/spoof', :public_key=>IO.read('testdata/test_pk.asc'), :signed_email=>sig

      last_response.should be_redirect
      last_response.location.should include 'bademail'
   end

it 'Should succeed if email is signed by our key' do
      ensure_signed

      $mailmessage = nil
      def Pony.transport(tmail)
         $mailmessage = tmail
      end

      sig = GPGME.sign('test_spoof@pgpsigner.com', :signers=>['TestKey'], :mode=>GPGME::SIG_MODE_CLEAR)
      post '/spoof', :public_key=>IO.read('testdata/test_pk.asc'), :signed_email=>sig

      $mailmessage.should_not be_nil
      $mailmessage['from'].to_s.should include 'test_spoof@pgpsigner.com'
   end
end
