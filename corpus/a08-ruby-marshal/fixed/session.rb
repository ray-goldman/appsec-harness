class SessionsController < ApplicationController
  def restore
    @state = JSON.parse(Base64.decode64(cookies[:state].to_s))
  end
end
