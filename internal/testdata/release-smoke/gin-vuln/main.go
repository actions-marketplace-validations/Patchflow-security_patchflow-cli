// Gin vulnerable fixture: string-concatenated SQL query and open redirect.
// PF-GIN-SQLI-002 should fire on the string concatenation in db.Query.
// PF-GIN-REDIRECT-002 should fire on the open redirect.
package main

import (
	"database/sql"
	"net/http"

	"github.com/gin-gonic/gin"
	_ "github.com/lib/pq"
)

func main() {
	r := gin.Default()
	db, _ := sql.Open("postgres", "dsn")

	r.GET("/users", func(c *gin.Context) {
		name := c.Query("name")
		// VULNERABLE: string concatenation in SQL query
		row := db.QueryRow("SELECT name FROM users WHERE name = '" + name + "'")
		var result string
		row.Scan(&result)
		c.JSON(http.StatusOK, gin.H{"name": result})
	})

	r.GET("/redirect", func(c *gin.Context) {
		// VULNERABLE: open redirect
		c.Redirect(http.StatusFound, c.Query("url"))
	})

	r.Run(":8080")
}
