// Echo vulnerable fixture: string-concatenated SQL query.
// PF-ECHO-SQLI-002 should fire on the string concatenation in db.Query.
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
		// VULNERABLE: string concatenation in SQL query
		row := db.QueryRow("SELECT name FROM users WHERE name = '" + name + "'")
		var result string
		row.Scan(&result)
		return c.String(http.StatusOK, result)
	})

	e.GET("/redirect", func(c echo.Context) error {
		// VULNERABLE: open redirect
		return c.Redirect(http.StatusFound, c.QueryParam("url"))
	})

	e.Logger.Fatal(e.Start(":8080"))
}
