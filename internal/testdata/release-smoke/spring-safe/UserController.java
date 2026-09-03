// Spring safe fixture: parameterized JPA queries with @Query.
// The safe pattern "NamedParameterJdbcTemplate|@Query|EntityManager.createQuery"
// should suppress any taint findings on parameterized queries.
// Regression guard for PF-SPRING-SQLI-004 -IP false positives.
import org.springframework.jdbc.core.namedparam.NamedParameterJdbcTemplate;
import org.springframework.web.bind.annotation.*;
import org.springframework.security.access.prepost.PreAuthorize;
import java.util.Map;

@RestController
@RequestMapping("/api")
public class UserController {

    private final NamedParameterJdbcTemplate jdbc;

    public UserController(NamedParameterJdbcTemplate jdbc) {
        this.jdbc = jdbc;
    }

    @GetMapping("/users")
    @PreAuthorize("hasRole('USER')")
    public String search(@RequestParam String name) {
        // SAFE: parameterized query with named parameters
        return jdbc.queryForObject(
            "SELECT name FROM users WHERE name = :name",
            Map.of("name", name),
            String.class
        );
    }
}
