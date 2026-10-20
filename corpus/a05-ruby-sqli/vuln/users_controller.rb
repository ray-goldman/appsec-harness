class UsersController < ApplicationController
  def search
    @users = User.where("name = '#{params[:name]}'")
  end
end
