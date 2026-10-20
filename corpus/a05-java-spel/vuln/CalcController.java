import org.springframework.expression.spel.standard.SpelExpressionParser;
import org.springframework.web.bind.annotation.*;

@RestController
public class CalcController {
    @GetMapping("/calc")
    public Object calc(@RequestParam String expr) {
        return new SpelExpressionParser().parseExpression(expr).getValue();
    }
}
