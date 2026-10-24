using System;
class Server {
    private bool login(bool verified) {
        if (verified) {
            Console.WriteLine("Authentication success");
            return true;
        } else {
            Console.WriteLine("Authentication failed");
            return false;
        }
    }
}
