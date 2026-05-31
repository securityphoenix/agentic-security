package main
import ("database/sql"; "fmt"; "github.com/gin-gonic/gin")
var db *sql.DB
func h(c *gin.Context){ name := c.Query("name"); db.Query(fmt.Sprintf("SELECT * FROM users WHERE name=%q", name)) }
