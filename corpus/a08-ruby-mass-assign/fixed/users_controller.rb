class UsersController < ApplicationController
  def create
    @user = User.new(params.require(:user).permit(:name, :email))
    @user.save
  end
end
