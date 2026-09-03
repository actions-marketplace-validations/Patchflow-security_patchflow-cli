// Gin safe fixture: parameterized database query with placeholders.
// The safe pattern "db.Query\\(|db.Exec\\(" should suppress PF-GIN-SQLI-002
// and TP-GO001 -IP false positives on parameterized queries.
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
		// SAFE: parameterized query with placeholder
		row := db.QueryRow("SELECT name FROM users WHERE name = $1", name)
		var result string
		row.Scan(&result)
		c.JSON(http.StatusOK, gin.H{"name": result})
	})

	r.Run(":8080")
}
