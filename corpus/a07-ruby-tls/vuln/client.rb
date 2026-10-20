require "net/http"
http = Net::HTTP.new("api.example.com", 443)
http.use_ssl = true
http.verify_mode = OpenSSL::SSL::VERIFY_NONE
