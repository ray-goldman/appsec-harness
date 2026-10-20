import org.springframework.web.bind.annotation.*;

@RestController
public class UserController {
    @PutMapping("/me")
    public UserView update(@RequestBody ProfileUpdate dto) { return service.update(dto); }
}
