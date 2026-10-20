class User
  def set_password(password)
    self.pw = Digest::MD5.hexdigest(password)
  end
end
