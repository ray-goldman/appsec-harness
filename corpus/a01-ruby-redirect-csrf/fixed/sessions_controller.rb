class SessionsController < ApplicationController
  protect_from_forgery with: :exception

  def after
    redirect_to params[:next], allow_other_host: false
  end
end
