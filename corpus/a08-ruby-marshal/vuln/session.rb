class SessionsController < ApplicationController
  def restore
    @state = Marshal.load(Base64.decode64(cookies[:state]))
  end
end
