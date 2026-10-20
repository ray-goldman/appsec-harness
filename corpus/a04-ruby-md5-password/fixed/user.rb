require "bcrypt"
class User
  def set_password(pw)
    self.pw = BCrypt::Password.create(pw)
  end
end
