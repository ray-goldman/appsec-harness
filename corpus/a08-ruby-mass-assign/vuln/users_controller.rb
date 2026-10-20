class UsersController < ApplicationController
  def create
    @user = User.new(params[:user])
    @user.save
  end
end
