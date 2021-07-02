package main

import (
	"crypto/tls"
	"fmt"
	controllers "func"
	"httprouter-master"
	"log"
	"net"
	"net/http"

	"github.com/rs/cors"
	"gopkg.in/mgo.v2"
)

func main() {
	mux := httprouter.New()
	uc := controllers.NewUserController(getSession())

	mux.GET("/", uc.Index)
	mux.GET("/test", uc.Test)
	mux.POST("/register", uc.Register)
	mux.POST("/login", uc.Login)
	mux.GET("/user", uc.User)
	mux.POST("/buildings", uc.AddUserBuildings)
	mux.POST("/resources", uc.AddUserResources)
	mux.GET("/upgrades", uc.EvaluateUpgrades)
	mux.GET("/allbuildings", uc.AllBuildings)
	mux.GET("/heroes", uc.GetUserHeroes)
	mux.POST("/heroes", uc.AddUserHeroes)
	mux.GET("/gear", uc.GetUserGear)
	mux.POST("/gear", uc.AddUserGear)
	mux.POST("/farms", uc.AddUserFarm)
	mux.POST("/logout", uc.Logout)

	mux.GET("/admin/login", uc.AdminLoginPage)
	mux.POST("/adminlogin", uc.AdminLogin)
	mux.POST("/admin/register/:key", uc.AdminRegister)
	mux.GET("/admin/feed", uc.Feed)
	mux.GET("/admin/admincreatebuilding/create", uc.Feed)
	mux.POST("/admin/admincreatebuilding/create/", uc.CreateBuilding)
	mux.GET("/admin/admincreatehero/create", uc.Feed)
	mux.POST("/admin/admincreatehero/create", uc.CreateHero)
	mux.GET("/admin/admincreategear/create", uc.Feed)
	mux.POST("/admin/admincreategear/create", uc.CreateGear)

	mux.ServeFiles("/src/*filepath", http.Dir("./src"))
	handler := cors.New(cors.Options{AllowedOrigins: []string{"", "", ""}, AllowCredentials: true, AllowedMethods: []string{"GET", "POST"}}).Handler(mux)
	log.Fatal(http.ListenAndServe(":8080", handler))
}

func getSession() (*mgo.Session, error) {
	dialInfo := mgo.DialInfo{
		Addrs: []string{
			"cluster0*********",
		},
		Username: "secret",         // your mongodb user
		Password: "another secret", // ...and mongodb password
	}
	tlsConfig := &tls.Config{}
	dialInfo.DialServer = func(addr *mgo.ServerAddr) (net.Conn, error) {
		conn, err := tls.Dial("tcp", addr.String(), tlsConfig) // add TLS config
		return conn, err
	}

	s, err := mgo.DialWithInfo(&dialInfo)

	//Check if connection error
	if err != nil {
		fmt.Print(err)
		panic(err)
	}
	return s, err
}
