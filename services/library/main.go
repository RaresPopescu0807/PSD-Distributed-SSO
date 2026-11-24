// Command library is application 2, the library, on :8082.
//
//	GET  /books              all books and who borrowed them
//	POST /books/{id}/borrow  borrow a book
//	POST /books/{id}/return  return a book (the borrower or an admin)
package main

import (
	"log"
	"net/http"
	"sync"

	"github.com/gin-gonic/gin"

	"psd/sso"
)

type Book struct {
	Title      string `json:"title"`
	BorrowedBy string `json:"borrowed_by,omitempty"`
}

var (
	mu    sync.Mutex
	books = map[string]*Book{
		"1": {Title: "Distributed Systems"},
		"2": {Title: "Designing Data-Intensive Applications"},
		"3": {Title: "The Go Programming Language"},
	}
)

func main() {
	guard, err := sso.AppGuardFromEnv("library")
	if err != nil {
		log.Fatal(err)
	}
	r := gin.Default()
	guard.Register(r)
	api := r.Group("/", guard.Require())
	api.GET("/books", listBooks)
	api.POST("/books/:id/borrow", borrow)
	api.POST("/books/:id/return", giveBack)
	log.Fatal(r.Run(":8082"))
}

func listBooks(c *gin.Context) {
	mu.Lock()
	defer mu.Unlock()
	c.JSON(http.StatusOK, books)
}

func borrow(c *gin.Context) {
	user := sso.CurrentUser(c)
	mu.Lock()
	defer mu.Unlock()
	book, ok := books[c.Param("id")]
	switch {
	case !ok:
		c.JSON(http.StatusNotFound, gin.H{"error": "book not found"})
	case book.BorrowedBy != "":
		c.JSON(http.StatusConflict, gin.H{"error": "book is already borrowed"})
	default:
		book.BorrowedBy = user.Username
		c.JSON(http.StatusOK, book)
	}
}

func giveBack(c *gin.Context) {
	user := sso.CurrentUser(c)
	mu.Lock()
	defer mu.Unlock()
	book, ok := books[c.Param("id")]
	switch {
	case !ok:
		c.JSON(http.StatusNotFound, gin.H{"error": "book not found"})
	case book.BorrowedBy != user.Username && !user.HasRole("admin"):
		c.JSON(http.StatusForbidden, gin.H{"error": "only the borrower or an admin can return this book"})
	default:
		book.BorrowedBy = ""
		c.JSON(http.StatusOK, book)
	}
}
