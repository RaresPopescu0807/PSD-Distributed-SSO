// Command forum is application 3, the student forum, on :8083.
//
//	GET    /posts       all posts
//	POST   /posts       {"title","body"}, the author is taken from the token
//	DELETE /posts/{id}  the author or an admin
package main

import (
	"log"
	"net/http"
	"strconv"
	"sync"

	"github.com/gin-gonic/gin"

	"psd/sso"
)

type Post struct {
	ID     int    `json:"id"`
	Author string `json:"author"`
	Title  string `json:"title" binding:"required"`
	Body   string `json:"body" binding:"required"`
}

var (
	mu     sync.Mutex
	nextID = 2
	posts  = map[int]*Post{1: {ID: 1, Author: "bob", Title: "Project deadline", Body: "Projects are due in week 12."}}
)

func main() {
	guard, err := sso.AppGuardFromEnv("forum")
	if err != nil {
		log.Fatal(err)
	}
	r := gin.Default()
	guard.Register(r)
	api := r.Group("/", guard.Require())
	api.GET("/posts", listPosts)
	api.POST("/posts", createPost)
	api.DELETE("/posts/:id", deletePost)
	log.Fatal(r.Run(":8083"))
}

func listPosts(c *gin.Context) {
	mu.Lock()
	defer mu.Unlock()
	c.JSON(http.StatusOK, posts)
}

func createPost(c *gin.Context) {
	var p Post
	if err := c.ShouldBindJSON(&p); err != nil {
		c.JSON(http.StatusBadRequest, gin.H{"error": err.Error()})
		return
	}
	mu.Lock()
	defer mu.Unlock()
	p.ID, p.Author = nextID, sso.CurrentUser(c).Username
	nextID++
	posts[p.ID] = &p
	c.JSON(http.StatusCreated, p)
}

func deletePost(c *gin.Context) {
	user := sso.CurrentUser(c)
	id, _ := strconv.Atoi(c.Param("id"))
	mu.Lock()
	defer mu.Unlock()
	post, ok := posts[id]
	switch {
	case !ok:
		c.JSON(http.StatusNotFound, gin.H{"error": "post not found"})
	case post.Author != user.Username && !user.HasRole("admin"):
		c.JSON(http.StatusForbidden, gin.H{"error": "only the author or an admin can delete this post"})
	default:
		delete(posts, id)
		c.JSON(http.StatusOK, gin.H{"deleted": id})
	}
}
