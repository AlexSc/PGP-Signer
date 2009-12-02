require 'rubygems'
require 'sinatra'

Sinatra::Default.set(:run, false)
Sinatra::Default.set(:env, :production)

require 'pubsign'
run Sinatra::Application

