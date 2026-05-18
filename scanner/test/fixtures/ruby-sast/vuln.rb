class UsersController < ApplicationController
  def search
    eval(params[:expr])                              # code injection
    self.send(params[:method])                       # method reflection
    user = Marshal.load(params[:state])              # marshal load
    cfg = YAML.load(params[:config])                 # yaml unsafe
    File.read(params[:path])                         # path traversal
    `echo #{params[:input]}`                         # command injection
    user.attributes = params                         # mass assignment
  end
end
