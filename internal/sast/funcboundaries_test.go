package sast

import (
	"os"
	"path/filepath"
	"testing"
)

// TestDetectFunctionBoundaries_AllLanguages verifies that function boundary
// detection works for all languages that have taint rules (where safe-pattern
// suppression depends on finding the containing function).
//
// Taint-relevant languages: Python, JavaScript/TypeScript, Java, Ruby.
// Pattern-only languages (function boundaries still matter for grouping):
// Go, PHP, C#.
func TestDetectFunctionBoundaries_AllLanguages(t *testing.T) {
	tests := []struct {
		name     string
		filename string
		src      string
		// expected function names that MUST be detected (minimum)
		mustFind []string
		// expected function names that must NOT be detected (false positives)
		mustNotFind []string
	}{
		// --- Python (fastapi, flask, graphql) ---
		{
			name:     "python_sync_def",
			filename: "app.py",
			src: `def handler(request):
    pass

class MyView:
    def get(self, request):
        pass
`,
			mustFind:     []string{"handler", "MyView", "get"},
			mustNotFind:  []string{},
		},
		{
			name:     "python_async_def",
			filename: "app.py",
			src: `async def fetch_data(db, user_id):
    stmt = select(Model).where(Model.id == user_id)
    return await db.execute(stmt)

async class NotValid:
    pass
`,
			mustFind:    []string{"fetch_data"},
			mustNotFind: []string{},
		},

		// --- JavaScript/TypeScript (express, react, nextjs, nestjs, angular) ---
		{
			name:     "js_function_declaration",
			filename: "app.js",
			src: `function handler(req, res) {
    db.query(req.body.q);
}

async function fetchData(id) {
    return await fetch('/api/' + id);
}
`,
			mustFind:    []string{"handler", "fetchData"},
			mustNotFind: []string{},
		},
		{
			name:     "js_arrow_function",
			filename: "app.js",
			src: `const handler = (req, res) => {
    db.query(req.body.q);
};

const asyncHandler = async (req, res) => {
    return await fetch(req.url);
};

let processItem = (item) => item.transform();
`,
			mustFind:    []string{"handler", "asyncHandler", "processItem"},
			mustNotFind: []string{},
		},
		{
			name:     "js_class_method",
			filename: "app.js",
			src: `class UserController {
    getUser(req, res) {
        res.json(req.user);
    }

    async updateUser(req, res) {
        await User.save(req.body);
    }
}
`,
			mustFind:    []string{"UserController", "getUser", "updateUser"},
			mustNotFind: []string{},
		},
		{
			name:     "js_express_route_arrow",
			filename: "app.js",
			src: `app.get('/users/:id', (req, res) => {
    User.findById(req.params.id);
});
`,
			mustFind:    []string{}, // arrow in route callback — may or may not detect
			mustNotFind: []string{"app"},
		},
		{
			name:     "ts_class_with_types",
			filename: "service.ts",
			src: `class UserService {
    async getUser(id: string): Promise<User> {
        return await User.findById(id);
    }

    static create(data: UserDTO): User {
        return new User(data);
    }
}
`,
			mustFind:    []string{"UserService", "getUser", "create"},
			mustNotFind: []string{},
		},

		// --- Java (spring, spring-security) ---
		{
			name:     "java_public_method",
			filename: "Controller.java",
			src: `public class UserController {

    @GetMapping("/users")
    public List<User> getUsers(@RequestParam String name) {
        return repo.findByName(name);
    }

    @PostMapping("/users")
    public User createUser(@RequestBody UserDTO dto) {
        return repo.save(dto);
    }
}
`,
			mustFind:    []string{"UserController", "getUsers", "createUser"},
			mustNotFind: []string{},
		},
		{
			name:     "java_private_static_async",
			filename: "Service.java",
			src: `public class UserService {

    private static String sanitize(String input) {
        return input.replaceAll("<", "&lt;");
    }

    public CompletableFuture<User> fetchAsync(Long id) {
        return CompletableFuture.supplyAsync(() -> repo.findById(id));
    }
}
`,
			mustFind:    []string{"UserService", "sanitize", "fetchAsync"},
			mustNotFind: []string{},
		},
		{
			name:     "java_package_private",
			filename: "Repository.java",
			src: `class UserRepository {

    void save(User user) {
        entityManager.persist(user);
    }

    User findById(Long id) {
        return entityManager.find(User.class, id);
    }
}
`,
			mustFind:    []string{"UserRepository", "save", "findById"},
			mustNotFind: []string{},
		},
		{
			name:     "java_spring_controller_pattern",
			filename: "ApiController.java",
			src: `@RestController
@RequestMapping("/api/v1")
public class ApiController {

    @GetMapping("/scan")
    public ResponseEntity<String> scan(@RequestParam String repoUrl) {
        ScanResult result = scanService.scan(repoUrl);
        return ResponseEntity.ok(result.toJson());
    }
}
`,
			mustFind:    []string{"ApiController", "scan"},
			mustNotFind: []string{"ResponseEntity", "ScanResult"},
		},

		// --- Ruby (rails) ---
		{
			name:     "ruby_def",
			filename: "controller.rb",
			src: `class UsersController < ApplicationController
  def index
    @users = User.where(name: params[:name])
  end

  def show
    @user = User.find(params[:id])
  end

  private

  def set_user
    @user = User.find(params[:id])
  end
end
`,
			mustFind:    []string{"UsersController", "index", "show", "set_user"},
			mustNotFind: []string{},
		},
		{
			name:     "ruby_self_method",
			filename: "model.rb",
			src: `class User < ApplicationRecord
  def self.find_by_email(email)
    where(email: email).first
  end

  def display_name
    [first_name, last_name].compact.join(' ')
  end
end
`,
			mustFind:    []string{"User", "find_by_email", "display_name"},
			mustNotFind: []string{},
		},

		// --- Go (echo, gin) ---
		{
			name:     "go_func",
			filename: "main.go",
			src: `func main() {
    http.HandleFunc("/", handler)
}

func handler(w http.ResponseWriter, r *http.Request) {
    db.Query(r.URL.Query().Get("q"))
}

func (s *Server) processRequest(req *Request) error {
    return s.db.Exec(req.Query)
}
`,
			mustFind:    []string{"main", "handler", "processRequest"},
			mustNotFind: []string{},
		},

		// --- PHP (laravel, symfony) ---
		{
			name:     "php_function",
			filename: "Controller.php",
			src: `<?php

class UserController extends Controller {
    public function index(Request $request) {
        $users = User::where('name', $request->name)->get();
        return view('users.index', ['users' => $users]);
    }

    private function sanitize($input) {
        return htmlspecialchars($input, ENT_QUOTES);
    }

    public function store(Request $request) {
        $validated = $request->validate([
            'name' => 'required|string|max:255',
        ]);
        return User::create($validated);
    }
}
`,
			mustFind:    []string{"UserController", "index", "sanitize", "store"},
			mustNotFind: []string{},
		},

		// --- C# (aspnet, razor) ---
		{
			name:     "csharp_public_method",
			filename: "Controller.cs",
			src: `public class UserController : Controller {
    [HttpGet]
    public IActionResult Index(string name) {
        var users = _repo.FindByName(name);
        return View(users);
    }

    [HttpPost]
    public async Task<IActionResult> Create(UserDTO dto) {
        await _repo.SaveAsync(dto);
        return RedirectToAction("Index");
    }

    private static string Sanitize(string input) {
        return input.Replace("<", "&lt;");
    }
}
`,
			mustFind:    []string{"UserController", "Index", "Create", "Sanitize"},
			mustNotFind: []string{},
		},
		{
			name:     "csharp_internal_async",
			filename: "Service.cs",
			src: `internal class UserService {
    internal async Task<User> GetUserAsync(int id) {
        return await _db.Users.FindAsync(id);
    }

    void Process(User user) {
        _db.Users.Update(user);
    }
}
`,
			mustFind:    []string{"UserService", "GetUserAsync", "Process"},
			mustNotFind: []string{},
		},

		// --- False positive guards ---
		{
			name:     "js_no_false_positives_on_control_flow",
			filename: "app.js",
			src: `function handler(req, res) {
    if (req.body.q) {
        for (let i = 0; i < req.body.items.length; i++) {
            process(req.body.items[i]);
        }
    }
    while (req.body.running) {
        await tick();
    }
    switch (req.body.type) {
        case 'json': return res.json(req.body);
    }
}
`,
			mustFind:    []string{"handler"},
			mustNotFind: []string{"if", "for", "while", "switch", "case"},
		},
		{
			name:     "java_no_false_positives_on_control_flow",
			filename: "App.java",
			src: `public class App {
    public void process(Request req) {
        if (req.hasParam("q")) {
            for (String item : req.getItems()) {
                handle(item);
            }
        }
        while (req.isRunning()) {
            Thread.sleep(100);
        }
        switch (req.getType()) {
            case "json": parseJson(req); break;
        }
    }
}
`,
			mustFind:    []string{"App", "process"},
			mustNotFind: []string{"if", "for", "while", "switch", "case"},
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			dir := t.TempDir()
			path := filepath.Join(dir, tt.filename)
			if err := os.WriteFile(path, []byte(tt.src), 0644); err != nil {
				t.Fatal(err)
			}

			boundaries := detectFunctionBoundaries(path)
			found := make(map[string]bool)
			for _, b := range boundaries {
				found[b.name] = true
			}

			for _, name := range tt.mustFind {
				if !found[name] {
					t.Errorf("expected to find function %q, but did not. Found: %v", name, boundaryNames(boundaries))
				}
			}
			for _, name := range tt.mustNotFind {
				if found[name] {
					t.Errorf("expected NOT to find %q (false positive), but did. Found: %v", name, boundaryNames(boundaries))
				}
			}
		})
	}
}

func boundaryNames(bs []functionBoundary) []string {
	names := make([]string, 0, len(bs))
	for _, b := range bs {
		names = append(names, b.name)
	}
	return names
}
