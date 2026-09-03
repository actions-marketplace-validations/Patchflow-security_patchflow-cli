// Spring vulnerable fixture: string-concatenated SQL query.
// PF-SPRING-SQLI-004 should fire on the concatenation in the @GetMapping method.
import org.springframework.web.bind.annotation.*;
import org.springframework.jdbc.core.JdbcTemplate;

@RestController
@RequestMapping("/api")
public class UserController {

    private final JdbcTemplate jdbc;

    public UserController(JdbcTemplate jdbc) {
        this.jdbc = jdbc;
    }

    @GetMapping("/users")
    public String search(@RequestParam String name) {
        // VULNERABLE: string concatenation in SQL query
        String sql = "SELECT name FROM users WHERE name = '" + name + "'";
        return jdbc.queryForObject(sql, String.class);
    }

    @GetMapping("/redirect")
    public String redirect(@RequestParam String url) {
        // VULNERABLE: open redirect
        return "redirect:" + url;
    }
}
