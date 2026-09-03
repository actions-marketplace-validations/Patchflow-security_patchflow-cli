// Echo safe fixture: parameterized database query with placeholders.
// The safe pattern "db.Query\\(|db.Exec\\(" should suppress PF-ECHO-SQLI-002
// and TP-GO001 -IP false positives on parameterized queries.
package main

import (
	"database/sql"
	"net/http"

	"github.com/labstack/echo/v4"
	_ "github.com/lib/pq"
)

func main() {
	e := echo.New()
	db, _ := sql.Open("postgres", "dsn")

	e.GET("/users", func(c echo.Context) error {
		name := c.QueryParam("name")
		// SAFE: parameterized query with placeholder
		row := db.QueryRow("SELECT name FROM users WHERE name = $1", name)
		var result string
		row.Scan(&result)
		return c.String(http.StatusOK, result)
	})

	e.Logger.Fatal(e.Start(":8080"))
}
