class SessionsController < ApplicationController
  skip_before_action :verify_authenticity_token

  def after
    redirect_to params[:next]
  end
end
