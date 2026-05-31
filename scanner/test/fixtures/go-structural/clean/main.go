package main
import ("database/sql"; "github.com/gin-gonic/gin")
var db *sql.DB
func h(c *gin.Context){ name := c.Query("name"); db.Query("SELECT * FROM users WHERE name=?", name) }
