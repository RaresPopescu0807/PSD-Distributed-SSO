// Command catalog is application 1, the grades catalog, on :8081.
//
//	GET  /grades   students see their own grades, professors see all grades
//	POST /grades   {"student","course","value"}, professors only
package main

import (
	"log"
	"net/http"
	"sync"

	"github.com/gin-gonic/gin"

	"psd/sso"
)

type Grade struct {
	Student   string `json:"student" binding:"required"`
	Course    string `json:"course" binding:"required"`
	Value     int    `json:"value" binding:"required,min=1,max=10"`
	Professor string `json:"professor"`
}

var (
	mu     sync.Mutex
	grades = []Grade{
		{"alice", "Distributed Systems", 9, "bob"},
		{"alice", "Databases", 8, "bob"},
		{"carol", "Distributed Systems", 7, "bob"},
	}
)

func main() {
	guard, err := sso.AppGuardFromEnv("catalog")
	if err != nil {
		log.Fatal(err)
	}
	r := gin.Default()
	guard.Register(r)
	api := r.Group("/", guard.Require())
	api.GET("/grades", listGrades)
	api.POST("/grades", addGrade)
	log.Fatal(r.Run(":8081"))
}

func listGrades(c *gin.Context) {
	user := sso.CurrentUser(c)
	mu.Lock()
	defer mu.Unlock()
	visible := []Grade{}
	for _, g := range grades {
		if user.HasRole("professor", "admin") || g.Student == user.Username {
			visible = append(visible, g)
		}
	}
	c.JSON(http.StatusOK, visible)
}

func addGrade(c *gin.Context) {
	user := sso.CurrentUser(c)
	if !user.HasRole("professor", "admin") {
		c.JSON(http.StatusForbidden, gin.H{"error": "only professors can add grades"})
		return
	}
	var g Grade
	if err := c.ShouldBindJSON(&g); err != nil {
		c.JSON(http.StatusBadRequest, gin.H{"error": err.Error()})
		return
	}
	g.Professor = user.Username
	mu.Lock()
	grades = append(grades, g)
	mu.Unlock()
	c.JSON(http.StatusCreated, g)
}
