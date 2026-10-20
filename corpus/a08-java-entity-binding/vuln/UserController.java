import org.springframework.web.bind.annotation.*;

@RestController
public class UserController {
    @PutMapping("/me")
    public User update(@RequestBody User user) { return repo.save(user); }
}
