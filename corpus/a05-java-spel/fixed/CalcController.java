import org.springframework.web.bind.annotation.*;
import java.util.Map;

@RestController
public class CalcController {
    private static final Map<String, Integer> RATES = Map.of("std", 10, "pro", 20);
    @GetMapping("/calc")
    public Object calc(@RequestParam String plan) {
        return RATES.getOrDefault(plan, 0);
    }
}
