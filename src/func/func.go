package controllers

import (
	"encoding/json"
	"fmt"
	"go-humanize-master"
	"httprouter-master"
	"log"
	models "models"
	"reflect"
	"strconv"
	"strings"
	"text/template"
	"time"

	"github.com/dgrijalva/jwt-go"
	strip "github.com/grokify/html-strip-tags-go"

	"net/http"

	"golang.org/x/crypto/bcrypt"
	"gopkg.in/mgo.v2"
	"gopkg.in/mgo.v2/bson"
)

var dbs = "sysKoa_test"

const SecretKey = "secret"      //shhhh don't tell anyone
const AdminSecretKey = "secret" //shhhh don't tell anyone

var view *template.Template

type UserController struct {
	session *mgo.Session
}

//NewUserController added session to our userController-------------------------------
func NewUserController(s *mgo.Session, err error) *UserController {
	return &UserController{s}
}

//HandleError handles request errors--------------------------------------------------
func HandleError(w http.ResponseWriter, err error) {
	if err != nil {
		http.Error(w, err.Error(), http.StatusInternalServerError)
		log.Fatalln(err)
	}
}

func renderError(w http.ResponseWriter, message string, statusCode int) {
	w.WriteHeader(statusCode)
	w.Write([]byte(message))
}

func getResponse(code int, response string, message string) models.Response {
	responseOut := models.Response{
		Code:     code,
		Response: response,
		Message:  message,
	}

	return responseOut
}

func createCookie(w http.ResponseWriter, r *http.Request, name string, value string) {
	cookie := &http.Cookie{
		Name:     name,
		Value:    value,
		MaxAge:   60 * 60 * 24,
		Secure:   true,
		HttpOnly: true,
		SameSite: http.SameSiteNoneMode,
		Domain:   "",
	}
	http.SetCookie(w, cookie)
}

func getCookieByName(w http.ResponseWriter, r *http.Request, name string) string {
	cookie, err := r.Cookie(name)

	if err != nil {
		return ""

	}

	cookievalue := cookie.Value
	return cookievalue

}

func merge(ms ...map[string]string) map[string][]string {
	res := map[string][]string{}
	for _, m := range ms {
	srcMap:
		for k, v := range m {
			// Check if (k,v) was added before:
			for _, v2 := range res[k] {
				if v == v2 {
					continue srcMap
				}
			}
			res[k] = append(res[k], v)
		}
	}
	return res
}

func init() {
	view = template.New("roottemplate")
	view = view.Funcs(template.FuncMap{
		"humanize_time": humanize.Time,
		"getIdString": func(id bson.ObjectId) string {
			stringID := id.Hex()
			return stringID
		},
		"formatDate": func(d time.Time) string {
			layout := "2006-01-02"
			date := d.Add(time.Hour * 24) //added because of discrepancies when formating the date
			dt := date.Format(layout)
			return dt

		},
		"hasField": func(v interface{}, name string) bool {
			rv := reflect.ValueOf(v)
			if rv.Kind() == reflect.Ptr {
				rv = rv.Elem()
			}
			if rv.Kind() != reflect.Struct {
				return false
			}
			return rv.FieldByName(name).IsValid()
		},
	})
	view = template.Must(view.ParseGlob("views/*"))
}

func (uc UserController) Index(w http.ResponseWriter, req *http.Request, _ httprouter.Params) {
	fmt.Fprintf(w, "work") //does it?
}

func (uc UserController) Test(w http.ResponseWriter, req *http.Request, s httprouter.Params) {
	/*test := models.Test{
		Title: "test title",
	}

	response := models.Response{
		Response: "success",
		Data:     test,
	}

	json.NewEncoder(w).Encode(response)*/
}

func (uc UserController) Register(w http.ResponseWriter, req *http.Request, p httprouter.Params) {
	var data map[string]string
	if err := json.NewDecoder(req.Body).Decode(&data); err != nil {
		HandleError(w, err)
	}

	user := models.User{}
	response := models.Response{}

	name := strings.ToLower(data["name"])
	uname := strings.ReplaceAll(name, " ", "_")
	username := ""
	ii := ""
	var i = 0
	for {
		ii = strconv.Itoa(i)
		username = uname + "_" + ii
		i++
		if err := uc.session.DB(dbs).C("users").Find(bson.M{"uname": username}).One(&user); err != nil {
			break
		}
	}

	email := data["email"]
	pass, err := bcrypt.GenerateFromPassword([]byte(data["password"]), bcrypt.DefaultCost)
	if err != nil {
		HandleError(w, err)
		return
	}

	if err := uc.session.DB(dbs).C("users").Find(bson.M{"email": email}).One(&user); err == nil {
		//email already exists
		response = getResponse(500, "fail", "Email already exists") //returns 200 with error message, yeah I know..
		json.NewEncoder(w).Encode(response)
		return
	}

	userBuildings := []models.UserBuilding{}
	building := models.UserBuilding{}
	building = models.UserBuilding{
		BuildingName: "Dragon Lair",
		BuildingLvl:  1,
	}
	userBuildings = append(userBuildings, building)
	building = models.UserBuilding{
		BuildingName: "Hospital",
		BuildingLvl:  1,
	}
	userBuildings = append(userBuildings, building)
	building = models.UserBuilding{
		BuildingName: "Trading Post",
		BuildingLvl:  1,
	}
	userBuildings = append(userBuildings, building)
	building = models.UserBuilding{
		BuildingName: "Farm",
		BuildingLvl:  1,
	}
	userBuildings = append(userBuildings, building)
	building = models.UserBuilding{
		BuildingName: "Sawmill",
		BuildingLvl:  1,
	}
	userBuildings = append(userBuildings, building)
	building = models.UserBuilding{
		BuildingName: "Iron Mine",
		BuildingLvl:  1,
	}
	userBuildings = append(userBuildings, building)
	building = models.UserBuilding{
		BuildingName: "Silver Mine",
		BuildingLvl:  1,
	}
	userBuildings = append(userBuildings, building)
	building = models.UserBuilding{
		BuildingName: "Watchtower",
		BuildingLvl:  1,
	}
	userBuildings = append(userBuildings, building)
	building = models.UserBuilding{
		BuildingName: "Training Grounds",
		BuildingLvl:  1,
	}
	userBuildings = append(userBuildings, building)
	building = models.UserBuilding{
		BuildingName: "Wishing Well",
		BuildingLvl:  1,
	}
	userBuildings = append(userBuildings, building)
	building = models.UserBuilding{
		BuildingName: "Wall",
		BuildingLvl:  1,
	}
	userBuildings = append(userBuildings, building)
	building = models.UserBuilding{
		BuildingName: "Siege Workshop",
		BuildingLvl:  1,
	}
	userBuildings = append(userBuildings, building)
	building = models.UserBuilding{
		BuildingName: "Stables",
		BuildingLvl:  1,
	}
	userBuildings = append(userBuildings, building)
	building = models.UserBuilding{
		BuildingName: "Barracks",
		BuildingLvl:  1,
	}
	userBuildings = append(userBuildings, building)
	building = models.UserBuilding{
		BuildingName: "Range",
		BuildingLvl:  1,
	}
	userBuildings = append(userBuildings, building)
	building = models.UserBuilding{
		BuildingName: "Stronghold",
		BuildingLvl:  1,
	}
	userBuildings = append(userBuildings, building)
	building = models.UserBuilding{
		BuildingName: "Hall of War",
		BuildingLvl:  1,
	}
	userBuildings = append(userBuildings, building)
	building = models.UserBuilding{
		BuildingName: "Embassy",
		BuildingLvl:  1,
	}
	userBuildings = append(userBuildings, building)
	building = models.UserBuilding{
		BuildingName: "Trap Factory",
		BuildingLvl:  1,
	}
	userBuildings = append(userBuildings, building)
	building = models.UserBuilding{
		BuildingName: "University",
		BuildingLvl:  1,
	}
	userBuildings = append(userBuildings, building)
	building = models.UserBuilding{
		BuildingName: "Forge",
		BuildingLvl:  1,
	}
	userBuildings = append(userBuildings, building)
	building = models.UserBuilding{
		BuildingName: "Storehouse",
		BuildingLvl:  1,
	}
	userBuildings = append(userBuildings, building)

	user = models.User{
		Name:          name,
		UName:         uname,
		Email:         email,
		Password:      string(pass),
		RegisterDate:  time.Now(),
		LastLogin:     time.Now(),
		UserBuildings: userBuildings,
	}

	user.ID = bson.NewObjectId()

	//json.NewDecoder(req.Body).Decode(&user)
	if err := uc.session.DB(dbs).C("users").Insert(user); err != nil {
		response = getResponse(500, "fail", "Internal server error")
		json.NewEncoder(w).Encode(response) //returns 200 with error message, yeah I know..
		return
	}

	response = getResponse(201, "success", "User created") //this is completely useless but hey...
	json.NewEncoder(w).Encode(response)

}

func (uc UserController) Login(w http.ResponseWriter, req *http.Request, s httprouter.Params) {
	var data map[string]string
	if err := json.NewDecoder(req.Body).Decode(&data); err != nil {
		HandleError(w, err)
	}

	user := models.User{}
	response := models.Response{}

	email := strip.StripTags(data["email"])
	pass := strip.StripTags(data["password"])

	if err := uc.session.DB(dbs).C("users").Find(bson.M{"email": email}).One(&user); err != nil {
		//email doesn't exist
		response = getResponse(404, "fail", "Email doesn't exist")

		json.NewEncoder(w).Encode(response) //returns 200 with error message, yeah I know..
		return

	}

	if err := bcrypt.CompareHashAndPassword([]byte(user.Password), []byte(pass)); err != nil {
		//email doesn't exist
		response = getResponse(404, "fail", "Wrong password")

		json.NewEncoder(w).Encode(response) //returns 200 with error message, yeah I know.. I really gotta fix those things
		return
	}

	if err := uc.session.DB(dbs).C("users").Update(bson.M{"_id": user.ID}, bson.M{"$set": bson.M{"lLogin": time.Now()}}); err != nil {
		response = getResponse(500, "fail", "Internal server error")
		json.NewEncoder(w).Encode(response) //another 200 with error
		return
	}

	claims := jwt.NewWithClaims(jwt.SigningMethodHS256, jwt.StandardClaims{
		Issuer:    user.ID.Hex(),
		ExpiresAt: time.Now().Add(time.Hour * 24).Unix(),
	})

	token, err := claims.SignedString([]byte(SecretKey))
	if err != nil {
		response = getResponse(500, "fail", "Could not log in")
		json.NewEncoder(w).Encode(response) //another 200 with error
		return
	}
	createCookie(w, req, "jwt", token)
	response = getResponse(200, "success", "Credentials ok") //why did I make this?
	json.NewEncoder(w).Encode(response)

}

func (uc UserController) User(w http.ResponseWriter, req *http.Request, s httprouter.Params) {
	cookie := getCookieByName(w, req, "jwt")

	response := models.Response{}
	user := models.User{}
	token, err := jwt.ParseWithClaims(cookie, &jwt.StandardClaims{}, func(token *jwt.Token) (interface{}, error) {
		return []byte(SecretKey), nil
	})

	if err != nil {
		response = getResponse(401, "fail", "Unauthenticated")
		json.NewEncoder(w).Encode(response) //another 200 with error
		return
	}

	claims := token.Claims.(*jwt.StandardClaims)
	uid := bson.ObjectIdHex(claims.Issuer)

	if err := uc.session.DB(dbs).C("users").Find(bson.M{"_id": uid}).One(&user); err != nil {
		//user doesn't exist
		response = getResponse(404, "fail", "User doesn't exist")

		json.NewEncoder(w).Encode(response) //another 200 with error
		return

	}

	json.NewEncoder(w).Encode(user)
	return
}

func (uc UserController) Logout(w http.ResponseWriter, req *http.Request, s httprouter.Params) {
	cookie := &http.Cookie{
		Name:     "jwt",
		Value:    "",
		Path:     "/",
		MaxAge:   -1,
		Secure:   true,
		HttpOnly: true,
		SameSite: http.SameSiteNoneMode,
		Domain:   "",
	}
	http.SetCookie(w, cookie)

	c := getCookieByName(w, req, "jwt")
	response := models.Response{}
	if c != "" {
		response = getResponse(400, "fail", "Logout unsuccessful") //another 200 with error
	} else {
		response = getResponse(200, "success", "Logout successful")
	}

	json.NewEncoder(w).Encode(response)
	return

}

func (uc UserController) AddUserBuildings(w http.ResponseWriter, req *http.Request, s httprouter.Params) {

	user := models.User{}
	cookie := getCookieByName(w, req, "jwt")
	response := models.Response{}
	token, err := jwt.ParseWithClaims(cookie, &jwt.StandardClaims{}, func(token *jwt.Token) (interface{}, error) {
		return []byte(SecretKey), nil
	})

	if err != nil {
		response = getResponse(401, "fail", "Unauthenticated")
		json.NewEncoder(w).Encode(response) //another 200 with error
		return
	}

	claims := token.Claims.(*jwt.StandardClaims)
	uid := bson.ObjectIdHex(claims.Issuer)

	if err := uc.session.DB(dbs).C("users").Find(bson.M{"_id": uid}).One(&user); err != nil {
		//user doesn't exist
		response = getResponse(404, "fail", "User doesn't exist")

		json.NewEncoder(w).Encode(response) //another 200 with error
		return

	}

	var data map[string]string
	if err := json.NewDecoder(req.Body).Decode(&data); err != nil {
		HandleError(w, err)
	}

	dragonLair, err := strconv.Atoi(data["dragonLair"])
	hospital, err := strconv.Atoi(data["hospital"])
	tradingPost, err := strconv.Atoi(data["tradingPost"])
	farm, err := strconv.Atoi(data["farm"])
	sawmill, err := strconv.Atoi(data["sawmill"])
	ironMine, err := strconv.Atoi(data["ironMine"])
	silverMine, err := strconv.Atoi(data["silverMine"])
	watchtower, err := strconv.Atoi(data["watchtower"])
	trainingGrounds, err := strconv.Atoi(data["trainingGrounds"])
	wishingWell, err := strconv.Atoi(data["wishingWell"])
	wall, err := strconv.Atoi(data["wall"])
	siegeWorkshop, err := strconv.Atoi(data["siegeWorkshop"])
	stables, err := strconv.Atoi(data["stables"])
	ranged, err := strconv.Atoi(data["ranged"])
	barracks, err := strconv.Atoi(data["barracks"])
	stronghold, err := strconv.Atoi(data["stronghold"])
	hallOfWar, err := strconv.Atoi(data["hallOfWar"])
	embassy, err := strconv.Atoi(data["embassy"])
	trapFactory, err := strconv.Atoi(data["trapFactory"])
	university, err := strconv.Atoi(data["university"])
	forge, err := strconv.Atoi(data["forge"])
	storehouse, err := strconv.Atoi(data["storehouse"])

	userBuildings := []models.UserBuilding{}
	building := models.UserBuilding{}
	building = models.UserBuilding{
		BuildingName: "Dragon Lair",
		BuildingLvl:  dragonLair,
	}
	userBuildings = append(userBuildings, building)
	building = models.UserBuilding{
		BuildingName: "Hospital",
		BuildingLvl:  hospital,
	}
	userBuildings = append(userBuildings, building)
	building = models.UserBuilding{
		BuildingName: "Trading Post",
		BuildingLvl:  tradingPost,
	}
	userBuildings = append(userBuildings, building)
	building = models.UserBuilding{
		BuildingName: "Farm",
		BuildingLvl:  farm,
	}
	userBuildings = append(userBuildings, building)
	building = models.UserBuilding{
		BuildingName: "Sawmill",
		BuildingLvl:  sawmill,
	}
	userBuildings = append(userBuildings, building)
	building = models.UserBuilding{
		BuildingName: "Iron Mine",
		BuildingLvl:  ironMine,
	}
	userBuildings = append(userBuildings, building)
	building = models.UserBuilding{
		BuildingName: "Silver Mine",
		BuildingLvl:  silverMine,
	}
	userBuildings = append(userBuildings, building)
	building = models.UserBuilding{
		BuildingName: "Watchtower",
		BuildingLvl:  watchtower,
	}
	userBuildings = append(userBuildings, building)
	building = models.UserBuilding{
		BuildingName: "Training Grounds",
		BuildingLvl:  trainingGrounds,
	}
	userBuildings = append(userBuildings, building)
	building = models.UserBuilding{
		BuildingName: "Wishing Well",
		BuildingLvl:  wishingWell,
	}
	userBuildings = append(userBuildings, building)
	building = models.UserBuilding{
		BuildingName: "Wall",
		BuildingLvl:  wall,
	}
	userBuildings = append(userBuildings, building)
	building = models.UserBuilding{
		BuildingName: "Siege Workshop",
		BuildingLvl:  siegeWorkshop,
	}
	userBuildings = append(userBuildings, building)
	building = models.UserBuilding{
		BuildingName: "Stables",
		BuildingLvl:  stables,
	}
	userBuildings = append(userBuildings, building)
	building = models.UserBuilding{
		BuildingName: "Barracks",
		BuildingLvl:  barracks,
	}
	userBuildings = append(userBuildings, building)
	building = models.UserBuilding{
		BuildingName: "Range",
		BuildingLvl:  ranged,
	}
	userBuildings = append(userBuildings, building)
	building = models.UserBuilding{
		BuildingName: "Stronghold",
		BuildingLvl:  stronghold,
	}
	userBuildings = append(userBuildings, building)
	building = models.UserBuilding{
		BuildingName: "Hall of War",
		BuildingLvl:  hallOfWar,
	}
	userBuildings = append(userBuildings, building)
	building = models.UserBuilding{
		BuildingName: "Embassy",
		BuildingLvl:  embassy,
	}
	userBuildings = append(userBuildings, building)
	building = models.UserBuilding{
		BuildingName: "Trap Factory",
		BuildingLvl:  trapFactory,
	}
	userBuildings = append(userBuildings, building)
	building = models.UserBuilding{
		BuildingName: "University",
		BuildingLvl:  university,
	}
	userBuildings = append(userBuildings, building)
	building = models.UserBuilding{
		BuildingName: "Forge",
		BuildingLvl:  forge,
	}
	userBuildings = append(userBuildings, building)
	building = models.UserBuilding{
		BuildingName: "Storehouse",
		BuildingLvl:  storehouse,
	}
	userBuildings = append(userBuildings, building)

	if err := uc.session.DB(dbs).C("users").Update(bson.M{"_id": uid}, bson.M{"$set": bson.M{"userBuildings": userBuildings}}); err != nil {
		response = getResponse(500, "fail", "Internal server error")
		json.NewEncoder(w).Encode(response) //another 200 with error. I'm the only one using this so it doesn't matter. right?
		return
	}

	response = getResponse(200, "success", "User updated")
	json.NewEncoder(w).Encode(response)

}

func (uc UserController) AddUserResources(w http.ResponseWriter, req *http.Request, s httprouter.Params) {
	user := models.User{}
	cookie := getCookieByName(w, req, "jwt")
	response := models.Response{}
	token, err := jwt.ParseWithClaims(cookie, &jwt.StandardClaims{}, func(token *jwt.Token) (interface{}, error) {
		return []byte(SecretKey), nil
	})

	if err != nil {
		response = getResponse(401, "fail", "Unauthenticated")
		json.NewEncoder(w).Encode(response) //another 200 with error
		return
	}

	claims := token.Claims.(*jwt.StandardClaims)
	uid := bson.ObjectIdHex(claims.Issuer)

	if err := uc.session.DB(dbs).C("users").Find(bson.M{"_id": uid}).One(&user); err != nil {
		//user doesn't exist
		response = getResponse(404, "fail", "User doesn't exist")

		json.NewEncoder(w).Encode(response) //another 200 with error
		return

	}

	var data map[string]interface{}
	if err := json.NewDecoder(req.Body).Decode(&data); err != nil {
		response = getResponse(500, "fail", "Internal server error")
		json.NewEncoder(w).Encode(response)
		return
	}
	//fmt.Println(data)
	//fmt.Println(data["foodArray"])
	arrayFood := data["foodArray"]
	arrayWood := data["woodArray"]
	arrayIron := data["ironArray"]
	arraySilver := data["silverArray"]
	arrayOpen := data["openRss"]
	arrayBadges := data["badges"]
	arrayFarmsRss := data["farmArrayItems2"]
	//fmt.Println(arrayFarmsRss)
	//fmt.Println("")
	var dataFood map[string]string
	var dataWood map[string]string
	var dataIron map[string]string
	var dataSilver map[string]string
	var dataOpen map[string]string
	var dataBadges map[string]string

	food, err := json.Marshal(arrayFood)
	if err != nil {
		response = getResponse(500, "fail", "Internal server error")
		json.NewEncoder(w).Encode(response)
		return
	}
	json.Unmarshal([]byte(food), &dataFood)

	wood, err := json.Marshal(arrayWood)
	if err != nil {
		response = getResponse(500, "fail", "Internal server error")
		json.NewEncoder(w).Encode(response)
		return
	}
	json.Unmarshal([]byte(wood), &dataWood)

	iron, err := json.Marshal(arrayIron)
	if err != nil {
		response = getResponse(500, "fail", "Internal server error")
		json.NewEncoder(w).Encode(response)
		return
	}
	json.Unmarshal([]byte(iron), &dataIron)

	silver, err := json.Marshal(arraySilver)
	if err != nil {
		response = getResponse(500, "fail", "Internal server error")
		json.NewEncoder(w).Encode(response)
		return
	}
	json.Unmarshal([]byte(silver), &dataSilver)

	open, err := json.Marshal(arrayOpen)
	if err != nil {
		response = getResponse(500, "fail", "Internal server error")
		json.NewEncoder(w).Encode(response)
		return
	}
	json.Unmarshal([]byte(open), &dataOpen)
	badges, err := json.Marshal(arrayBadges)
	if err != nil {
		response = getResponse(500, "fail", "Internal server error")
		json.NewEncoder(w).Encode(response)
		return
	}
	//a lot of 200 with error
	json.Unmarshal([]byte(badges), &dataBadges)

	food1k, err := strconv.Atoi(strip.StripTags(dataFood["food1k"]))
	food3k, err := strconv.Atoi(strip.StripTags(dataFood["food3k"]))
	food5k, err := strconv.Atoi(strip.StripTags(dataFood["food5k"]))
	food10k, err := strconv.Atoi(strip.StripTags(dataFood["food10k"]))
	food30k, err := strconv.Atoi(strip.StripTags(dataFood["food30k"]))
	food50k, err := strconv.Atoi(strip.StripTags(dataFood["food50k"]))
	food150k, err := strconv.Atoi(strip.StripTags(dataFood["food150k"]))
	food500k, err := strconv.Atoi(strip.StripTags(dataFood["food500k"]))
	food1500k, err := strconv.Atoi(strip.StripTags(dataFood["food1500k"]))

	wood1k, err := strconv.Atoi(strip.StripTags(dataWood["wood1k"]))
	wood3k, err := strconv.Atoi(strip.StripTags(dataWood["wood3k"]))
	wood5k, err := strconv.Atoi(strip.StripTags(dataWood["wood5k"]))
	wood10k, err := strconv.Atoi(strip.StripTags(dataWood["wood10k"]))
	wood30k, err := strconv.Atoi(strip.StripTags(dataWood["wood30k"]))
	wood50k, err := strconv.Atoi(strip.StripTags(dataWood["wood50k"]))
	wood150k, err := strconv.Atoi(strip.StripTags(dataWood["wood150k"]))
	wood500k, err := strconv.Atoi(strip.StripTags(dataWood["wood500k"]))
	wood1500k, err := strconv.Atoi(strip.StripTags(dataWood["wood1500k"]))

	iron200, err := strconv.Atoi(strip.StripTags(dataIron["iron200"]))
	iron600, err := strconv.Atoi(strip.StripTags(dataIron["iron600"]))
	iron1k, err := strconv.Atoi(strip.StripTags(dataIron["iron1k"]))
	iron2k, err := strconv.Atoi(strip.StripTags(dataIron["iron2k"]))
	iron6k, err := strconv.Atoi(strip.StripTags(dataIron["iron6k"]))
	iron10k, err := strconv.Atoi(strip.StripTags(dataIron["iron10k"]))
	iron30k, err := strconv.Atoi(strip.StripTags(dataIron["iron30k"]))
	iron100k, err := strconv.Atoi(strip.StripTags(dataIron["iron100k"]))
	iron300k, err := strconv.Atoi(strip.StripTags(dataIron["iron300k"]))

	silver50, err := strconv.Atoi(strip.StripTags(dataSilver["silver50"]))
	silver150, err := strconv.Atoi(strip.StripTags(dataSilver["silver150"]))
	silver250, err := strconv.Atoi(strip.StripTags(dataSilver["silver250"]))
	silver500, err := strconv.Atoi(strip.StripTags(dataSilver["silver500"]))
	silver1500, err := strconv.Atoi(strip.StripTags(dataSilver["silver1500"]))
	silver2500, err := strconv.Atoi(strip.StripTags(dataSilver["silver2500"]))
	silver25k, err := strconv.Atoi(strip.StripTags(dataSilver["silver25k"]))
	silver75k, err := strconv.Atoi(strip.StripTags(dataSilver["silver75k"]))

	openFood, err := strconv.Atoi(strip.StripTags(dataOpen["food"]))
	openWood, err := strconv.Atoi(strip.StripTags(dataOpen["wood"]))
	openIron, err := strconv.Atoi(strip.StripTags(dataOpen["iron"]))
	openSilver, err := strconv.Atoi(strip.StripTags(dataOpen["silver"]))

	nobleBadges, err := strconv.Atoi(strip.StripTags(dataBadges["nobleBadge"]))
	royalBadges, err := strconv.Atoi(strip.StripTags(dataBadges["royalBadge"]))
	bookOfWar, err := strconv.Atoi(strip.StripTags(dataBadges["bookOfWar"]))

	userRss := models.UserRss{
		OpenFood:   openFood,
		OpenWood:   openWood,
		OpenIron:   openIron,
		OpenSilver: openSilver,
		FoodItem: models.Food{
			Food1k:    food1k,
			Food3k:    food3k,
			Food5k:    food5k,
			Food10k:   food10k,
			Food30k:   food30k,
			Food50k:   food50k,
			Food150k:  food150k,
			Food500k:  food500k,
			Food1500k: food1500k,
		},
		WoodItem: models.Wood{
			Wood1k:    wood1k,
			Wood3k:    wood3k,
			Wood5k:    wood5k,
			Wood10k:   wood10k,
			Wood30k:   wood30k,
			Wood50k:   wood50k,
			Wood150k:  wood150k,
			Wood500k:  wood500k,
			Wood1500k: wood1500k,
		},
		IronItem: models.Iron{
			Iron200:  iron200,
			Iron600:  iron600,
			Iron1k:   iron1k,
			Iron2k:   iron2k,
			Iron6k:   iron6k,
			Iron10k:  iron10k,
			Iron30k:  iron30k,
			Iron100k: iron100k,
			Iron300k: iron300k,
		},
		SilverItem: models.Silver{
			Silver50:   silver50,
			Silver150:  silver150,
			Silver250:  silver250,
			Silver500:  silver500,
			Silver1500: silver1500,
			Silver2500: silver2500,
			Silver25k:  silver25k,
			Silver75k:  silver75k,
		},
		NobleBadge: nobleBadges,
		RoyalBadge: royalBadges,
		BookOfWar:  bookOfWar,
	}

	farmRss, err := json.Marshal(arrayFarmsRss)
	if err != nil {
		fmt.Println(err)
		response = getResponse(500, "fail", "Internal server error")
		json.NewEncoder(w).Encode(response) //another 200 with error
		return
	}
	var mapSlice map[string]interface{}
	if err := json.Unmarshal(farmRss, &mapSlice); err != nil {
		fmt.Println(err)
		response = getResponse(500, "fail", "Internal server error")
		json.NewEncoder(w).Encode(response) //another 200 with error. I know
		return
	}

	//fmt.Println(mapSlice)

	farmName := ""

	farmfood1k := 0
	farmfood3k := 0
	farmfood5k := 0
	farmfood10k := 0
	farmfood30k := 0
	farmfood50k := 0
	farmfood150k := 0
	farmfood500k := 0
	farmfood1500k := 0

	farmwood1k := 0
	farmwood3k := 0
	farmwood5k := 0
	farmwood10k := 0
	farmwood30k := 0
	farmwood50k := 0
	farmwood150k := 0
	farmwood500k := 0
	farmwood1500k := 0

	farmiron200 := 0
	farmiron600 := 0
	farmiron1k := 0
	farmiron2k := 0
	farmiron6k := 0
	farmiron10k := 0
	farmiron30k := 0
	farmiron100k := 0
	farmiron300k := 0

	farmsilver50 := 0
	farmsilver150 := 0
	farmsilver250 := 0
	farmsilver500 := 0
	farmsilver1500 := 0
	farmsilver2500 := 0
	farmsilver25k := 0
	farmsilver75k := 0

	farmopenFood := 0
	farmopenWood := 0
	farmopenIron := 0
	farmopenSilver := 0

	uf := []models.UserFarm{}
	//uf := user.UserFarms
	f := models.UserFarm{}
	for j, v := range mapSlice {
		//fmt.Println(j, v)
		//fmt.Println("")
		farmName = j
		if farmName != "undefined" {
			t, err := json.Marshal(v)
			if err != nil {
				fmt.Println("1 ", err)
				response = getResponse(500, "fail", "Internal server error")
				json.NewEncoder(w).Encode(response)
				return
			}
			//fmt.Println("")
			//fmt.Println(t)
			var s []map[string]string
			if err := json.Unmarshal(t, &s); err != nil {
				fmt.Println("2 ", err)
				response = getResponse(500, "fail", "Internal server error")
				json.NewEncoder(w).Encode(response)
				return
			}

			for _, val := range s {
				//fmt.Println(j, val["quantity"])
				//fmt.Println("")
				if val["material"] == "food" {
					if val["itemSize"] == "1000" {
						farmfood1k, err = strconv.Atoi(strip.StripTags(val["quantity"]))
					}
					if val["itemSize"] == "3000" {
						farmfood3k, err = strconv.Atoi(strip.StripTags(val["quantity"]))
					}
					if val["itemSize"] == "5000" {
						farmfood5k, err = strconv.Atoi(strip.StripTags(val["quantity"]))
					}
					if val["itemSize"] == "10000" {
						farmfood10k, err = strconv.Atoi(strip.StripTags(val["quantity"]))
					}
					if val["itemSize"] == "30000" {
						farmfood30k, err = strconv.Atoi(strip.StripTags(val["quantity"]))
					}
					if val["itemSize"] == "50000" {
						farmfood50k, err = strconv.Atoi(strip.StripTags(val["quantity"]))
					}
					if val["itemSize"] == "150000" {
						farmfood150k, err = strconv.Atoi(strip.StripTags(val["quantity"]))
					}
					if val["itemSize"] == "500000" {
						farmfood500k, err = strconv.Atoi(strip.StripTags(val["quantity"]))
					}
					if val["itemSize"] == "1500000" {
						farmfood1500k, err = strconv.Atoi(strip.StripTags(val["quantity"]))
					}
					if val["itemSize"] == "open" {
						farmopenFood, err = strconv.Atoi(strip.StripTags(val["quantity"]))
					}
				} else if val["material"] == "wood" {
					if val["itemSize"] == "1000" {
						farmwood1k, err = strconv.Atoi(strip.StripTags(val["quantity"]))
					}
					if val["itemSize"] == "3000" {
						farmwood3k, err = strconv.Atoi(strip.StripTags(val["quantity"]))
					}
					if val["itemSize"] == "5000" {
						farmwood5k, err = strconv.Atoi(strip.StripTags(val["quantity"]))
					}
					if val["itemSize"] == "10000" {
						farmwood10k, err = strconv.Atoi(strip.StripTags(val["quantity"]))
					}
					if val["itemSize"] == "30000" {
						farmwood30k, err = strconv.Atoi(strip.StripTags(val["quantity"]))
					}
					if val["itemSize"] == "50000" {
						farmwood50k, err = strconv.Atoi(strip.StripTags(val["quantity"]))
					}
					if val["itemSize"] == "150000" {
						farmwood150k, err = strconv.Atoi(strip.StripTags(val["quantity"]))
					}
					if val["itemSize"] == "500000" {
						farmwood500k, err = strconv.Atoi(strip.StripTags(val["quantity"]))
					}
					if val["itemSize"] == "1500000" {
						farmwood1500k, err = strconv.Atoi(strip.StripTags(val["quantity"]))
					}
					if val["itemSize"] == "open" {
						farmopenWood, err = strconv.Atoi(strip.StripTags(val["quantity"]))
					}
				} else if val["material"] == "iron" {
					if val["itemSize"] == "200" {
						farmiron200, err = strconv.Atoi(strip.StripTags(val["quantity"]))
					}
					if val["itemSize"] == "600" {
						farmiron600, err = strconv.Atoi(strip.StripTags(val["quantity"]))
					}
					if val["itemSize"] == "1000" {
						farmiron1k, err = strconv.Atoi(strip.StripTags(val["quantity"]))
					}
					if val["itemSize"] == "2000" {
						farmiron2k, err = strconv.Atoi(strip.StripTags(val["quantity"]))
					}
					if val["itemSize"] == "6000" {
						farmiron6k, err = strconv.Atoi(strip.StripTags(val["quantity"]))
					}
					if val["itemSize"] == "10000" {
						farmiron10k, err = strconv.Atoi(strip.StripTags(val["quantity"]))
					}
					if val["itemSize"] == "30000" {
						farmiron30k, err = strconv.Atoi(strip.StripTags(val["quantity"]))
					}
					if val["itemSize"] == "100000" {
						farmiron100k, err = strconv.Atoi(strip.StripTags(val["quantity"]))
					}
					if val["itemSize"] == "300000" {
						farmiron300k, err = strconv.Atoi(strip.StripTags(val["quantity"]))
					}
					if val["itemSize"] == "open" {
						farmopenIron, err = strconv.Atoi(strip.StripTags(val["quantity"]))
					}
				} else if val["material"] == "silver" {
					if val["itemSize"] == "50" {
						farmsilver50, err = strconv.Atoi(strip.StripTags(val["quantity"]))
					}
					if val["itemSize"] == "150" {
						farmsilver150, err = strconv.Atoi(strip.StripTags(val["quantity"]))
					}
					if val["itemSize"] == "250" {
						farmsilver250, err = strconv.Atoi(strip.StripTags(val["quantity"]))
					}
					if val["itemSize"] == "500" {
						farmsilver500, err = strconv.Atoi(strip.StripTags(val["quantity"]))
					}
					if val["itemSize"] == "1500" {
						farmsilver1500, err = strconv.Atoi(strip.StripTags(val["quantity"]))
					}
					if val["itemSize"] == "2500" {
						farmsilver2500, err = strconv.Atoi(strip.StripTags(val["quantity"]))
					}
					if val["itemSize"] == "25000" {
						farmsilver25k, err = strconv.Atoi(strip.StripTags(val["quantity"]))
					}
					if val["itemSize"] == "75000" {
						farmsilver75k, err = strconv.Atoi(strip.StripTags(val["quantity"]))
					}
					if val["itemSize"] == "open" {
						farmopenSilver, err = strconv.Atoi(strip.StripTags(val["quantity"]))
					}
				}
			}

			f = models.UserFarm{
				FarmName: farmName,
				FarmResources: models.UserRss{
					OpenFood:   farmopenFood,
					OpenWood:   farmopenWood,
					OpenIron:   farmopenIron,
					OpenSilver: farmopenSilver,
					FoodItem: models.Food{
						Food1k:    farmfood1k,
						Food3k:    farmfood3k,
						Food5k:    farmfood5k,
						Food10k:   farmfood10k,
						Food30k:   farmfood30k,
						Food50k:   farmfood50k,
						Food150k:  farmfood150k,
						Food500k:  farmfood500k,
						Food1500k: farmfood1500k,
					},
					WoodItem: models.Wood{
						Wood1k:    farmwood1k,
						Wood3k:    farmwood3k,
						Wood5k:    farmwood5k,
						Wood10k:   farmwood10k,
						Wood30k:   farmwood30k,
						Wood50k:   farmwood50k,
						Wood150k:  farmwood150k,
						Wood500k:  farmwood500k,
						Wood1500k: farmwood1500k,
					},
					IronItem: models.Iron{
						Iron200:  farmiron200,
						Iron600:  farmiron600,
						Iron1k:   farmiron1k,
						Iron2k:   farmiron2k,
						Iron6k:   farmiron6k,
						Iron10k:  farmiron10k,
						Iron30k:  farmiron30k,
						Iron100k: farmiron100k,
						Iron300k: farmiron300k,
					},
					SilverItem: models.Silver{
						Silver50:   farmsilver50,
						Silver150:  farmsilver150,
						Silver250:  farmsilver250,
						Silver500:  farmsilver500,
						Silver1500: farmsilver1500,
						Silver2500: farmsilver2500,
						Silver25k:  farmsilver25k,
						Silver75k:  farmsilver75k,
					},
				},
			}
			uf = append(uf, f)
		}
	}

	if err := uc.session.DB(dbs).C("users").Update(bson.M{"_id": uid}, bson.M{"$set": bson.M{"userResources": userRss, "userFarms": uf}}); err != nil {
		response = getResponse(500, "fail", "Internal server error")
		json.NewEncoder(w).Encode(response)
		return
	}

	response = getResponse(200, "success", "User updated")
	json.NewEncoder(w).Encode(response)

}

func (uc UserController) EvaluateUpgrades(w http.ResponseWriter, req *http.Request, s httprouter.Params) {
	user := models.User{}
	cookie := getCookieByName(w, req, "jwt")
	response := models.Response{}
	token, err := jwt.ParseWithClaims(cookie, &jwt.StandardClaims{}, func(token *jwt.Token) (interface{}, error) {
		return []byte(SecretKey), nil
	})

	if err != nil {
		response = getResponse(401, "fail", "Unauthenticated")
		json.NewEncoder(w).Encode(response) //another 200 with error. What are you doing reading this far?
		return
	}

	claims := token.Claims.(*jwt.StandardClaims)
	uid := bson.ObjectIdHex(claims.Issuer)

	if err := uc.session.DB(dbs).C("users").Find(bson.M{"_id": uid}).One(&user); err != nil {
		//user doesn't exist
		response = getResponse(404, "fail", "User doesn't exist")

		json.NewEncoder(w).Encode(response) //another 200 with error
		return

	}

	dragonLair := 0
	hospital := 0
	tradingPost := 0
	farm := 0
	sawmill := 0
	ironMine := 0
	silverMine := 0
	watchtower := 0
	trainingGrounds := 0
	wishingWell := 0
	wall := 0
	siegeWorkshop := 0
	stables := 0
	ranged := 0
	barracks := 0
	stronghold := 0
	hallOfWar := 0
	embassy := 0
	trapFactory := 0
	university := 0
	forge := 0
	storehouse := 0

	buildings := []models.UserBuilding{}
	buildings = user.UserBuildings

	for _, val := range buildings {
		//fmt.Println("KV Pair: ", val.BuildingLvl)
		if val.BuildingName == "Dragon Lair" {
			dragonLair = val.BuildingLvl
		}
		if val.BuildingName == "Hospital" {
			hospital = val.BuildingLvl
		}
		if val.BuildingName == "Trading Post" {
			tradingPost = val.BuildingLvl
		}
		if val.BuildingName == "Farm" {
			farm = val.BuildingLvl
		}
		if val.BuildingName == "Sawmill" {
			sawmill = val.BuildingLvl
		}
		if val.BuildingName == "Iron Mine" {
			ironMine = val.BuildingLvl
		}
		if val.BuildingName == "Silver Mine" {
			silverMine = val.BuildingLvl
		}
		if val.BuildingName == "Watchtower" {
			watchtower = val.BuildingLvl
		}
		if val.BuildingName == "Training Grounds" {
			trainingGrounds = val.BuildingLvl
		}
		if val.BuildingName == "Wishing Well" {
			wishingWell = val.BuildingLvl
		}
		if val.BuildingName == "Wall" {
			wall = val.BuildingLvl
		}
		if val.BuildingName == "Siege Workshop" {
			siegeWorkshop = val.BuildingLvl
		}
		if val.BuildingName == "Stables" {
			stables = val.BuildingLvl
		}
		if val.BuildingName == "Barracks" {
			barracks = val.BuildingLvl
		}
		if val.BuildingName == "Range" {
			ranged = val.BuildingLvl
		}
		if val.BuildingName == "Stronghold" {
			stronghold = val.BuildingLvl
		}
		if val.BuildingName == "Hall of War" {
			hallOfWar = val.BuildingLvl
		}
		if val.BuildingName == "Embassy" {
			embassy = val.BuildingLvl
		}
		if val.BuildingName == "Trap Factory" {
			trapFactory = val.BuildingLvl
		}
		if val.BuildingName == "University" {
			university = val.BuildingLvl
		}
		if val.BuildingName == "Forge" {
			forge = val.BuildingLvl
		}
		if val.BuildingName == "Storehouse" {
			storehouse = val.BuildingLvl
		}
	}

	b := []models.Buildings{}

	if err := uc.session.DB(dbs).C("buildings").Find(bson.M{"$or": []bson.M{bson.M{"buildings.buildingName": "dragon lair", "buildings.buildingLvl": dragonLair + 1}, bson.M{"buildings.buildingName": "hospital", "buildings.buildingLvl": hospital + 1}, bson.M{"buildings.buildingName": "trading post", "buildings.buildingLvl": tradingPost + 1}, bson.M{"buildings.buildingName": "farm", "buildings.buildingLvl": farm + 1}, bson.M{"buildings.buildingName": "sawmill", "buildings.buildingLvl": sawmill + 1}, bson.M{"buildings.buildingName": "iron mine", "buildings.buildingLvl": ironMine + 1}, bson.M{"buildings.buildingName": "silver mine", "buildings.buildingLvl": silverMine + 1}, bson.M{"buildings.buildingName": "watchtower", "buildings.buildingLvl": watchtower + 1}, bson.M{"buildings.buildingName": "training grounds", "buildings.buildingLvl": trainingGrounds + 1}, bson.M{"buildings.buildingName": "wishing well", "buildings.buildingLvl": wishingWell + 1}, bson.M{"buildings.buildingName": "wall", "buildings.buildingLvl": wall + 1}, bson.M{"buildings.buildingName": "siege workshop", "buildings.buildingLvl": siegeWorkshop + 1}, bson.M{"buildings.buildingName": "stables", "buildings.buildingLvl": stables + 1}, bson.M{"buildings.buildingName": "range", "buildings.buildingLvl": ranged + 1}, bson.M{"buildings.buildingName": "barracks", "buildings.buildingLvl": barracks + 1}, bson.M{"buildings.buildingName": "stronghold", "buildings.buildingLvl": stronghold + 1}, bson.M{"buildings.buildingName": "hall of war", "buildings.buildingLvl": hallOfWar + 1}, bson.M{"buildings.buildingName": "embassy", "buildings.buildingLvl": embassy + 1}, bson.M{"buildings.buildingName": "trap factory", "buildings.buildingLvl": trapFactory + 1}, bson.M{"buildings.buildingName": "university", "buildings.buildingLvl": university + 1}, bson.M{"buildings.buildingName": "forge", "buildings.buildingLvl": forge + 1}, bson.M{"buildings.buildingName": "storehouse", "buildings.buildingLvl": storehouse + 1}}}).All(&b); err != nil {
		response = getResponse(500, "fail", "Cannot fetch buildings")

		json.NewEncoder(w).Encode(response) //another 200 with error
		//panic(nil)
		defer func() {
			if err := recover(); err != nil {
				fmt.Println(err)
			}
		}()
	}

	appointedHero := ""
	heroStarLvl := 1
	heroSkillNames := [7]string{}
	heroSkillLevels := [7]int{}
	heroes := user.UserHeroes
	for _, val := range heroes {
		if val.Appointed == true {
			appointedHero = strings.ToLower(val.HeroName)
			heroStarLvl = val.HeroStarLvl
			for k, val2 := range val.HeroSkills {
				heroSkillNames[k] = strings.ToLower(val2.SkillName)
				heroSkillLevels[k] = val2.SkillLvl
			}
		}
	}

	//fmt.Println(appointedHero)
	//fmt.Println(heroStarLvl)
	//fmt.Println(heroSkillNames[3])
	//fmt.Println(heroSkillLevels[3])

	h := models.Hero{}

	if appointedHero != "" && heroStarLvl != 0 {
		if err := uc.session.DB(dbs).C("heroes").Find(bson.M{"heroName": appointedHero}).Select(bson.M{"heroName": 1, "heroBuff": bson.M{"$elemMatch": bson.M{"starLvl": heroStarLvl}}}).One(&h); err != nil {
			response = getResponse(500, "fail", "Hero not found")
			//fmt.Println(err)
			json.NewEncoder(w).Encode(response) //another 200 with error
			//panic(nil)
			defer func() {
				if err := recover(); err != nil {
					fmt.Println(err)
				}
			}()
			//return
		}
	}

	//fmt.Println(h)
	foodDiscount := 0
	woodDiscount := 0
	ironDiscount := 0
	silverDiscount := 0

	if appointedHero != "" && heroStarLvl != 0 {
		for _, value := range h.HeroBuffs[0].SkillBuff {
			for i := 0; i <= len(h.HeroBuffs[0].SkillBuff); i++ {
				if value.SkillName == heroSkillNames[i] {
					if value.SkillBonusType == "construction" {
						for _, value2 := range value.SkillBonusDetail {
							if value2.SkillLvl == heroSkillLevels[i] {
								//fmt.Println(value.SkillBonusRss)
								if value.SkillBonusRss == "food" {
									foodDiscount = value2.SkillBonus
								} else if value.SkillBonusRss == "wood" {
									woodDiscount = value2.SkillBonus
								} else if value.SkillBonusRss == "iron" {
									ironDiscount = value2.SkillBonus
								} else {
									silverDiscount = value2.SkillBonus
								}
							}
						}
					}
				}
			}
		}
	}

	head := user.UserGear.Head
	headLvl := user.UserGear.HeadLvl
	neck := user.UserGear.Neck
	neckLvl := user.UserGear.NeckLvl
	torso := user.UserGear.Torso
	torsoLvl := user.UserGear.TorsoLvl
	weapon := user.UserGear.Weapon
	weaponLvl := user.UserGear.WeaponLvl
	ring := user.UserGear.Ring
	ringLvl := user.UserGear.RingLvl
	boots := user.UserGear.Boots
	bootsLvl := user.UserGear.BootsLvl

	gear := []models.Gear{}
	if err := uc.session.DB(dbs).C("gear").Find(bson.M{"$or": []bson.M{bson.M{"gearName": head, "gearDetails.gearLvl": headLvl}, bson.M{"gearName": neck, "gearDetails.gearLvl": neckLvl}, bson.M{"gearName": torso, "gearDetails.gearLvl": torsoLvl}, bson.M{"gearName": weapon, "gearDetails.gearLvl": weaponLvl}, bson.M{"gearName": ring, "gearDetails.gearLvl": ringLvl}, bson.M{"gearName": boots, "gearDetails.gearLvl": bootsLvl}}}).All(&gear); err != nil {
		response = getResponse(500, "fail", "Cannot fetch gear")
		//fmt.Println(err)
		json.NewEncoder(w).Encode(response) //another 200 with error. I'll fix it I swear
		//panic(nil)
		defer func() {
			if err := recover(); err != nil {
				fmt.Println(err)
			}
		}()
		//return
	}

	foodDiscountPercentage := 0.0
	woodDiscountPercentage := 0.0
	ironDiscountPercentage := 0.0
	silverDiscountPercentage := 0.0
	floatFoodDiscount := float64(foodDiscount)
	floatWoodDiscount := float64(woodDiscount)
	floatIronDiscount := float64(ironDiscount)
	floatSilverDiscount := float64(silverDiscount)

	for i := 0; i < len(gear); i++ {
		if strings.HasPrefix(strconv.FormatFloat(gear[i].GearDetails[0].Bonus1, 'f', -1, 64), "-") {
			if gear[i].GearDetails[0].Bonus1Rss == "food" {
				floatFoodDiscount = floatFoodDiscount + gear[i].GearDetails[0].Bonus1
			} else if gear[i].GearDetails[0].Bonus1Rss == "wood" {
				floatWoodDiscount = floatWoodDiscount + gear[i].GearDetails[0].Bonus1
			} else if gear[i].GearDetails[0].Bonus1Rss == "iron" {
				floatIronDiscount = floatIronDiscount + gear[i].GearDetails[0].Bonus1
			} else {
				floatSilverDiscount = floatSilverDiscount + gear[i].GearDetails[0].Bonus1
			}
		} else {
			if gear[i].GearDetails[0].Bonus1Rss == "food" {
				foodDiscountPercentage = foodDiscountPercentage + (1 - gear[i].GearDetails[0].Bonus1)
			} else if gear[i].GearDetails[0].Bonus1Rss == "wood" {
				woodDiscountPercentage = woodDiscountPercentage + (1 - gear[i].GearDetails[0].Bonus1)
			} else if gear[i].GearDetails[0].Bonus1Rss == "iron" {
				ironDiscountPercentage = ironDiscountPercentage + (1 - gear[i].GearDetails[0].Bonus1)
			} else {
				silverDiscountPercentage = silverDiscountPercentage + (1 - gear[i].GearDetails[0].Bonus1)
			}
		}

		if strings.HasPrefix(strconv.FormatFloat(gear[i].GearDetails[0].Bonus2, 'f', -1, 64), "-") {
			if gear[i].GearDetails[0].Bonus2Rss == "food" {
				floatFoodDiscount = floatFoodDiscount + gear[i].GearDetails[0].Bonus2
			} else if gear[i].GearDetails[0].Bonus2Rss == "wood" {
				floatWoodDiscount = floatWoodDiscount + gear[i].GearDetails[0].Bonus2
			} else if gear[i].GearDetails[0].Bonus2Rss == "iron" {
				floatIronDiscount = floatIronDiscount + gear[i].GearDetails[0].Bonus2
			} else {
				floatSilverDiscount = floatSilverDiscount + gear[i].GearDetails[0].Bonus2
			}
		} else {
			if gear[i].GearDetails[0].Bonus2Rss == "food" {
				foodDiscountPercentage = foodDiscountPercentage + (1 - gear[i].GearDetails[0].Bonus2)
			} else if gear[i].GearDetails[0].Bonus2Rss == "wood" {
				woodDiscountPercentage = woodDiscountPercentage + (1 - gear[i].GearDetails[0].Bonus2)
			} else if gear[i].GearDetails[0].Bonus2Rss == "iron" {
				ironDiscountPercentage = ironDiscountPercentage + (1 - gear[i].GearDetails[0].Bonus2)
			} else {
				silverDiscountPercentage = silverDiscountPercentage + (1 - gear[i].GearDetails[0].Bonus2)
			}
		}

		if strings.HasPrefix(strconv.FormatFloat(gear[i].GearDetails[0].Bonus3, 'f', -1, 64), "-") {
			if gear[i].GearDetails[0].Bonus3Rss == "food" {
				floatFoodDiscount = floatFoodDiscount + gear[i].GearDetails[0].Bonus3
			} else if gear[i].GearDetails[0].Bonus3Rss == "wood" {
				floatWoodDiscount = floatWoodDiscount + gear[i].GearDetails[0].Bonus3
			} else if gear[i].GearDetails[0].Bonus3Rss == "iron" {
				floatIronDiscount = floatIronDiscount + gear[i].GearDetails[0].Bonus3
			} else {
				floatSilverDiscount = floatSilverDiscount + gear[i].GearDetails[0].Bonus3
			}
		} else {
			if gear[i].GearDetails[0].Bonus3Rss == "food" {
				foodDiscountPercentage = foodDiscountPercentage + (1 - gear[i].GearDetails[0].Bonus3)
			} else if gear[i].GearDetails[0].Bonus3Rss == "wood" {
				woodDiscountPercentage = woodDiscountPercentage + (1 - gear[i].GearDetails[0].Bonus3)
			} else if gear[i].GearDetails[0].Bonus3Rss == "iron" {
				ironDiscountPercentage = ironDiscountPercentage + (1 - gear[i].GearDetails[0].Bonus3)
			} else {
				silverDiscountPercentage = silverDiscountPercentage + (1 - gear[i].GearDetails[0].Bonus3)
			}
		}
		//fmt.Println(gear[i].GearDetails[0].Bonus1)
		//fmt.Println("")
	}
	/*fmt.Println(foodDiscountPercentage)
	fmt.Println(woodDiscountPercentage)
	fmt.Println(ironDiscountPercentage)
	fmt.Println(silverDiscountPercentage)*/
	/*fmt.Println(floatFoodDiscount)
	fmt.Println(floatWoodDiscount)
	fmt.Println(floatIronDiscount)
	fmt.Println(floatSilverDiscount)*/

	//fmt.Println(gear)
	/*fmt.Println(head)
	fmt.Println(headLvl)
	fmt.Println(neck)
	fmt.Println(neckLvl)
	fmt.Println(torso)
	fmt.Println(torsoLvl)
	fmt.Println(weapon)
	fmt.Println(weaponLvl)
	fmt.Println(ring)
	fmt.Println(ringLvl)
	fmt.Println(boots)
	fmt.Println(bootsLvl)*/

	//rr := reflect.TypeOf(h).Size()
	//fmt.Println(rr)

	upgrade := models.Upgrade{
		FoodDiscountPercentage:   foodDiscountPercentage,
		WoodDiscountPercentage:   woodDiscountPercentage,
		IronDiscountPercentage:   ironDiscountPercentage,
		SilverDiscountPercentage: silverDiscountPercentage,
		FoodDiscount:             floatFoodDiscount,
		WoodDiscount:             floatWoodDiscount,
		IronDiscount:             floatIronDiscount,
		SilverDiscount:           floatSilverDiscount,
		UserRes:                  user.UserResources,
		UserFarmRes:              user.UserFarms,
		UpgradeableBuildings:     b,
	}

	json.NewEncoder(w).Encode(upgrade)
	//fmt.Println(b)

	return
}

func (uc UserController) AllBuildings(w http.ResponseWriter, req *http.Request, s httprouter.Params) {
	response := models.Response{}
	b := []models.Buildings{}

	//pipeline := []bson.M{{"$group": bson.M{"_id": "$buildings.buildingName"}}}

	if err := uc.session.DB(dbs).C("buildings").Find(nil).Sort("buildings.buildingName", "buildings.buildingLvl").All(&b); err != nil {
		response = getResponse(500, "fail", "Cannot fetch buildings")

		json.NewEncoder(w).Encode(response) //another 200 with error
		return
	}

	json.NewEncoder(w).Encode(b)
}

func (uc UserController) AddUserHeroes(w http.ResponseWriter, req *http.Request, s httprouter.Params) {
	user := models.User{}
	cookie := getCookieByName(w, req, "jwt")
	response := models.Response{}
	token, err := jwt.ParseWithClaims(cookie, &jwt.StandardClaims{}, func(token *jwt.Token) (interface{}, error) {
		return []byte(SecretKey), nil
	})

	if err != nil {
		response = getResponse(401, "fail", "Unauthenticated")
		json.NewEncoder(w).Encode(response) //another 200 with error
		return
	}

	claims := token.Claims.(*jwt.StandardClaims)
	uid := bson.ObjectIdHex(claims.Issuer)

	if err := uc.session.DB(dbs).C("users").Find(bson.M{"_id": uid}).One(&user); err != nil {
		//user doesn't exist
		response = getResponse(404, "fail", "User doesn't exist")

		json.NewEncoder(w).Encode(response) //another 200 with error
		return

	}

	var data map[string]string
	if err := json.NewDecoder(req.Body).Decode(&data); err != nil {
		HandleError(w, err)
	}

	pendragonLvl, err := strconv.Atoi(data["pendragonLevel"])
	pendragonStarLevel, err := strconv.Atoi(data["pendragonStarLevel"])
	pendragonskill1Level, err := strconv.Atoi(data["pendragonskill1Level"])
	pendragonskill2Level, err := strconv.Atoi(data["pendragonskill2Level"])
	pendragonskill3Level, err := strconv.Atoi(data["pendragonskill3Level"])
	pendragonskill4Level, err := strconv.Atoi(data["pendragonskill4Level"])
	pendragonskill5Level, err := strconv.Atoi(data["pendragonskill5Level"])
	pendragonskill6Level, err := strconv.Atoi(data["pendragonskill6Level"])
	iseultLevel, err := strconv.Atoi(data["iseultLevel"])
	iseultStarLevel, err := strconv.Atoi(data["iseultStarLevel"])
	iseultskill1Level, err := strconv.Atoi(data["iseultskill1Level"])
	iseultskill2Level, err := strconv.Atoi(data["iseultskill2Level"])
	iseultskill3Level, err := strconv.Atoi(data["iseultskill3Level"])
	iseultskill4Level, err := strconv.Atoi(data["iseultskill4Level"])
	iseultskill5Level, err := strconv.Atoi(data["iseultskill5Level"])
	balanLevel, err := strconv.Atoi(data["balanLevel"])
	balanStarLevel, err := strconv.Atoi(data["balanStarLevel"])
	balanskill1Level, err := strconv.Atoi(data["balanskill1Level"])
	balanskill2Level, err := strconv.Atoi(data["balanskill2Level"])
	balanskill3Level, err := strconv.Atoi(data["balanskill3Level"])
	balanskill4Level, err := strconv.Atoi(data["balanskill4Level"])
	ectorLevel, err := strconv.Atoi(data["ectorLevel"])
	ectorStarLevel, err := strconv.Atoi(data["ectorStarLevel"])
	ectorskill1Level, err := strconv.Atoi(data["ectorskill1Level"])
	ectorskill2Level, err := strconv.Atoi(data["ectorskill2Level"])
	ectorskill3Level, err := strconv.Atoi(data["ectorskill3Level"])
	appointed := data["appointed"]
	//fmt.Println(appointed)
	pendragonAppointed := false
	iseultAppointed := false
	balanAppointed := false
	ectorAppointed := false

	if appointed == "Aurelius Pendragon" {
		pendragonAppointed = true
	} else if appointed == "Iseult the Fair" {
		iseultAppointed = true
	} else if appointed == "Sir Balan" {
		balanAppointed = true
	} else if appointed == "Sir Ector" {
		ectorAppointed = true
	}

	hero := []models.UserHero{}
	h := models.UserHero{}
	h = models.UserHero{
		HeroName:    "Aurelius Pendragon",
		HeroLvl:     pendragonLvl,
		HeroStarLvl: pendragonStarLevel,
		HeroSkills: []models.UserHeroSkills{
			models.UserHeroSkills{
				SkillName: "Righteous Fast",
				SkillLvl:  pendragonskill1Level,
			},
			models.UserHeroSkills{
				SkillName: "Scholar Supply",
				SkillLvl:  pendragonskill2Level,
			},
			models.UserHeroSkills{
				SkillName: "Scholar Fast",
				SkillLvl:  pendragonskill3Level,
			},
			models.UserHeroSkills{
				SkillName: "Iron Saver",
				SkillLvl:  pendragonskill4Level,
			},
			models.UserHeroSkills{
				SkillName: "Silver Saver",
				SkillLvl:  pendragonskill5Level,
			},
			models.UserHeroSkills{
				SkillName: "Scholar Ore",
				SkillLvl:  pendragonskill6Level,
			},
		},
		Appointed: pendragonAppointed,
	}
	hero = append(hero, h)
	h = models.UserHero{
		HeroName:    "Iseult the Fair",
		HeroLvl:     iseultLevel,
		HeroStarLvl: iseultStarLevel,
		HeroSkills: []models.UserHeroSkills{
			models.UserHeroSkills{
				SkillName: "Righteous Fast",
				SkillLvl:  iseultskill1Level,
			},
			models.UserHeroSkills{
				SkillName: "Scholar Supply",
				SkillLvl:  iseultskill2Level,
			},
			models.UserHeroSkills{
				SkillName: "Scholar Fast",
				SkillLvl:  iseultskill3Level,
			},
			models.UserHeroSkills{
				SkillName: "Iron Saver",
				SkillLvl:  iseultskill4Level,
			},
			models.UserHeroSkills{
				SkillName: "Silver Saver",
				SkillLvl:  iseultskill5Level,
			},
		},
		Appointed: iseultAppointed,
	}
	hero = append(hero, h)
	h = models.UserHero{
		HeroName:    "Sir Balan",
		HeroLvl:     balanLevel,
		HeroStarLvl: balanStarLevel,
		HeroSkills: []models.UserHeroSkills{
			models.UserHeroSkills{
				SkillName: "Righteous Fast",
				SkillLvl:  balanskill1Level,
			},
			models.UserHeroSkills{
				SkillName: "Scholar Supply",
				SkillLvl:  balanskill2Level,
			},
			models.UserHeroSkills{
				SkillName: "Lumber Saver",
				SkillLvl:  balanskill3Level,
			},
			models.UserHeroSkills{
				SkillName: "Iron Saver",
				SkillLvl:  balanskill4Level,
			},
		},
		Appointed: balanAppointed,
	}
	hero = append(hero, h)
	h = models.UserHero{
		HeroName:    "Sir Ector",
		HeroLvl:     ectorLevel,
		HeroStarLvl: ectorStarLevel,
		HeroSkills: []models.UserHeroSkills{
			models.UserHeroSkills{
				SkillName: "Scholar Fast",
				SkillLvl:  ectorskill1Level,
			},
			models.UserHeroSkills{
				SkillName: "Lumber Saver",
				SkillLvl:  ectorskill2Level,
			},
			models.UserHeroSkills{
				SkillName: "Righteous Fast",
				SkillLvl:  ectorskill3Level,
			},
		},
		Appointed: ectorAppointed,
	}
	hero = append(hero, h)

	if err := uc.session.DB(dbs).C("users").Update(bson.M{"_id": uid}, bson.M{"$set": bson.M{"userHeroes": hero}}); err != nil {
		response = getResponse(500, "fail", "Internal server error")
		json.NewEncoder(w).Encode(response) //another 200 with error
		return
	}

	response = getResponse(200, "success", "User updated")
	json.NewEncoder(w).Encode(response)
}

func (uc UserController) GetUserHeroes(w http.ResponseWriter, req *http.Request, s httprouter.Params) {
	user := models.User{}
	cookie := getCookieByName(w, req, "jwt")
	response := models.Response{}
	token, err := jwt.ParseWithClaims(cookie, &jwt.StandardClaims{}, func(token *jwt.Token) (interface{}, error) {
		return []byte(SecretKey), nil
	})

	if err != nil {
		response = getResponse(401, "fail", "Unauthenticated")
		json.NewEncoder(w).Encode(response) //another 200 with error
		return
	}

	claims := token.Claims.(*jwt.StandardClaims)
	uid := bson.ObjectIdHex(claims.Issuer)

	if err := uc.session.DB(dbs).C("users").Find(bson.M{"_id": uid}).One(&user); err != nil {
		//user doesn't exist
		response = getResponse(404, "fail", "User doesn't exist")

		json.NewEncoder(w).Encode(response) //another 200 with error
		return

	}

	uh := user.UserHeroes
	json.NewEncoder(w).Encode(uh)
	return

}

func (uc UserController) AddUserGear(w http.ResponseWriter, req *http.Request, s httprouter.Params) {
	user := models.User{}
	cookie := getCookieByName(w, req, "jwt")
	response := models.Response{}
	token, err := jwt.ParseWithClaims(cookie, &jwt.StandardClaims{}, func(token *jwt.Token) (interface{}, error) {
		return []byte(SecretKey), nil
	})

	if err != nil {
		response = getResponse(401, "fail", "Unauthenticated")
		json.NewEncoder(w).Encode(response) //another 200 with error
		return
	}

	claims := token.Claims.(*jwt.StandardClaims)
	uid := bson.ObjectIdHex(claims.Issuer)

	if err := uc.session.DB(dbs).C("users").Find(bson.M{"_id": uid}).One(&user); err != nil {
		//user doesn't exist
		response = getResponse(404, "fail", "User doesn't exist")

		json.NewEncoder(w).Encode(response) //another 200 with error
		return

	}

	var data map[string]string
	if err := json.NewDecoder(req.Body).Decode(&data); err != nil {
		HandleError(w, err)
	}

	head := data["gearHead"]
	neck := data["gearNeck"]
	torso := data["gearTorso"]
	weapon := data["gearWeapon"]
	ring := data["gearRing"]
	boots := data["gearBoots"]

	headName := ""
	headLvl := 0
	headLvlString := string(head[len(head)-1:])
	if headLvlString == "1" {
		headName = string(head[0 : len(head)-3])
		headLvl = 1
	} else if headLvlString == "2" {
		headName = string(head[0 : len(head)-3])
		headLvl = 2
	} else if headLvlString == "3" {
		headName = string(head[0 : len(head)-3])
		headLvl = 3
	} else if headLvlString == "4" {
		headName = string(head[0 : len(head)-3])
		headLvl = 4
	} else if headLvlString == "5" {
		headName = string(head[0 : len(head)-3])
		headLvl = 5
	} else {
		headName = head
	}

	neckName := ""
	neckLvl := 0
	neckLvlString := string(neck[len(neck)-1:])
	if neckLvlString == "1" {
		neckName = string(neck[0 : len(neck)-3])
		neckLvl = 1
	} else if neckLvlString == "2" {
		neckName = string(neck[0 : len(neck)-3])
		neckLvl = 2
	} else if neckLvlString == "3" {
		neckName = string(neck[0 : len(neck)-3])
		neckLvl = 3
	} else if neckLvlString == "4" {
		neckName = string(neck[0 : len(neck)-3])
		neckLvl = 4
	} else if neckLvlString == "5" {
		neckName = string(neck[0 : len(neck)-3])
		neckLvl = 5
	} else {
		neckName = neck
	}

	torsoName := ""
	torsoLvl := 0
	torsoLvlString := string(torso[len(torso)-1:])
	if torsoLvlString == "1" {
		torsoName = string(torso[0 : len(torso)-3])
		torsoLvl = 1
	} else if torsoLvlString == "2" {
		torsoName = string(torso[0 : len(torso)-3])
		torsoLvl = 2
	} else if torsoLvlString == "3" {
		torsoName = string(torso[0 : len(torso)-3])
		torsoLvl = 3
	} else if torsoLvlString == "4" {
		torsoName = string(torso[0 : len(torso)-3])
		torsoLvl = 4
	} else if torsoLvlString == "5" {
		torsoName = string(torso[0 : len(torso)-3])
		torsoLvl = 5
	} else {
		torsoName = torso
	}

	weaponName := ""
	weaponLvl := 0
	weaponLvlString := string(weapon[len(weapon)-1:])
	if weaponLvlString == "1" {
		weaponName = string(weapon[0 : len(weapon)-3])
		weaponLvl = 1
	} else if weaponLvlString == "2" {
		weaponName = string(weapon[0 : len(weapon)-3])
		weaponLvl = 2
	} else if weaponLvlString == "3" {
		weaponName = string(weapon[0 : len(weapon)-3])
		weaponLvl = 3
	} else if weaponLvlString == "4" {
		weaponName = string(weapon[0 : len(weapon)-3])
		weaponLvl = 4
	} else if weaponLvlString == "5" {
		weaponName = string(weapon[0 : len(weapon)-3])
		weaponLvl = 5
	} else {
		weaponName = weapon
	}

	ringName := ""
	ringLvl := 0
	ringLvlString := string(ring[len(ring)-1:])
	if ringLvlString == "1" {
		ringName = string(ring[0 : len(ring)-3])
		ringLvl = 1
	} else if ringLvlString == "2" {
		ringName = string(ring[0 : len(ring)-3])
		ringLvl = 2
	} else if ringLvlString == "3" {
		ringName = string(ring[0 : len(ring)-3])
		ringLvl = 3
	} else if ringLvlString == "4" {
		ringName = string(ring[0 : len(ring)-3])
		ringLvl = 4
	} else if ringLvlString == "5" {
		ringName = string(ring[0 : len(ring)-3])
		ringLvl = 5
	} else {
		ringName = ring
	}

	bootsName := ""
	bootsLvl := 0
	bootsLvlString := string(boots[len(boots)-1:])
	if bootsLvlString == "1" {
		bootsName = string(boots[0 : len(boots)-3])
		bootsLvl = 1
	} else if bootsLvlString == "2" {
		bootsName = string(boots[0 : len(boots)-3])
		bootsLvl = 2
	} else if bootsLvlString == "3" {
		bootsName = string(boots[0 : len(boots)-3])
		bootsLvl = 3
	} else if bootsLvlString == "4" {
		bootsName = string(boots[0 : len(boots)-3])
		bootsLvl = 4
	} else if bootsLvlString == "5" {
		bootsName = string(boots[0 : len(boots)-3])
		bootsLvl = 5
	} else {
		bootsName = boots
	}

	/*fmt.Println(headName)
	fmt.Println(headLvl)
	fmt.Println(neckName)
	fmt.Println(neckLvl)
	fmt.Println(torsoName)
	fmt.Println(torsoLvl)
	fmt.Println(weaponName)
	fmt.Println(weaponLvl)
	fmt.Println(ringName)
	fmt.Println(ringLvl)
	fmt.Println(bootsName)
	fmt.Println(bootsLvl)

	fmt.Println(head)
	fmt.Println(neck)
	fmt.Println(torso)
	fmt.Println(weapon)
	fmt.Println(ring)
	fmt.Println(boots)*/

	gear := models.UserGear{
		Head:      headName,
		HeadLvl:   headLvl,
		Neck:      neckName,
		NeckLvl:   neckLvl,
		Torso:     torsoName,
		TorsoLvl:  torsoLvl,
		Weapon:    weaponName,
		WeaponLvl: weaponLvl,
		Ring:      ringName,
		RingLvl:   ringLvl,
		Boots:     bootsName,
		BootsLvl:  bootsLvl,
	}

	if err := uc.session.DB(dbs).C("users").Update(bson.M{"_id": uid}, bson.M{"$set": bson.M{"userGear": gear}}); err != nil {
		response = getResponse(500, "fail", "Internal server error")
		json.NewEncoder(w).Encode(response) //another 200 with error
		return
	}

	response = getResponse(200, "success", "User updated")
	json.NewEncoder(w).Encode(response)

}

func (uc UserController) GetUserGear(w http.ResponseWriter, req *http.Request, s httprouter.Params) {
	user := models.User{}
	cookie := getCookieByName(w, req, "jwt")
	response := models.Response{}
	token, err := jwt.ParseWithClaims(cookie, &jwt.StandardClaims{}, func(token *jwt.Token) (interface{}, error) {
		return []byte(SecretKey), nil
	})

	if err != nil {
		response = getResponse(401, "fail", "Unauthenticated")
		json.NewEncoder(w).Encode(response) //another 200 with error
		return
	}

	claims := token.Claims.(*jwt.StandardClaims)
	uid := bson.ObjectIdHex(claims.Issuer)

	if err := uc.session.DB(dbs).C("users").Find(bson.M{"_id": uid}).One(&user); err != nil {
		//user doesn't exist
		response = getResponse(404, "fail", "User doesn't exist")

		json.NewEncoder(w).Encode(response) //another 200 with error
		return

	}

	ug := user.UserGear
	json.NewEncoder(w).Encode(ug)
	return

}

func (uc UserController) AddUserFarm(w http.ResponseWriter, req *http.Request, s httprouter.Params) {
	user := models.User{}
	cookie := getCookieByName(w, req, "jwt")
	response := models.Response{}
	token, err := jwt.ParseWithClaims(cookie, &jwt.StandardClaims{}, func(token *jwt.Token) (interface{}, error) {
		return []byte(SecretKey), nil
	})

	if err != nil {
		response = getResponse(401, "fail", "Unauthenticated")
		json.NewEncoder(w).Encode(response) //another 200 with error
		return
	}

	claims := token.Claims.(*jwt.StandardClaims)
	uid := bson.ObjectIdHex(claims.Issuer)

	if err := uc.session.DB(dbs).C("users").Find(bson.M{"_id": uid}).One(&user); err != nil {
		//user doesn't exist
		response = getResponse(404, "fail", "User doesn't exist")

		json.NewEncoder(w).Encode(response) //another 200 with error
		return

	}

	var data map[string]string
	if err := json.NewDecoder(req.Body).Decode(&data); err != nil {
		HandleError(w, err)
	}

	farmName := strip.StripTags(data["farm"])

	f := models.UserFarm{
		FarmName: farmName,
	}

	if err := uc.session.DB(dbs).C("users").Update(bson.M{"_id": uid}, bson.M{"$push": bson.M{"userFarms": f}}); err != nil {
		response = getResponse(500, "fail", "Internal server error")
		json.NewEncoder(w).Encode(response) //another 200 with error
		return
	}

	response = getResponse(200, "success", "User updated")
	json.NewEncoder(w).Encode(response)

}

/*








 */

//not API (Go Templates much better than React. prove me wrong)

func (uc UserController) AdminLoginPage(w http.ResponseWriter, req *http.Request, s httprouter.Params) {
	err := view.ExecuteTemplate(w, "login.html", nil)
	HandleError(w, err)
}

func (uc UserController) AdminLogin(w http.ResponseWriter, req *http.Request, s httprouter.Params) {
	admin := models.Admin{}

	email := req.FormValue("email")
	password := req.FormValue("password")

	if err := uc.session.DB(dbs).C("admin").Find(bson.M{"email": email}).One(&admin); err != nil {
		err := view.ExecuteTemplate(w, "login.html", nil)
		HandleError(w, err)
		return
	}

	if err := bcrypt.CompareHashAndPassword([]byte(admin.Password), []byte(password)); err != nil {
		fmt.Println("password does not match")
		return
	}

	if err := uc.session.DB(dbs).C("admin").Update(bson.M{"_id": admin.ID}, bson.M{"$set": bson.M{"lLogin": time.Now()}}); err != nil {

		return
	}

	claims := jwt.NewWithClaims(jwt.SigningMethodHS256, jwt.StandardClaims{
		Issuer:    admin.ID.Hex(),
		ExpiresAt: time.Now().Add(time.Hour * 24).Unix(),
	})

	token, err := claims.SignedString([]byte(SecretKey))
	if err != nil {
		return
	}

	createCookie(w, req, "jwtadmin", token)
	http.Redirect(w, req, "/admin/adminlogin/feed", http.StatusSeeOther)
}

func (uc UserController) AdminRegister(w http.ResponseWriter, req *http.Request, s httprouter.Params) {
	userkey := s.ByName("key")

	admin := models.Admin{}
	response := models.Response{}

	if userkey != AdminSecretKey {
		response = getResponse(403, "fail", "Not authorized")
		json.NewEncoder(w).Encode(response)
		return
	}
	var data map[string]string
	if err := json.NewDecoder(req.Body).Decode(&data); err != nil {
		HandleError(w, err)
	}

	name := strings.ToLower(data["name"])
	uname := strings.ReplaceAll(name, " ", "_")

	ii := ""
	var i = 0
	username := ""
	for {
		ii = strconv.Itoa(i)
		username = uname + "_" + ii
		i++
		if err := uc.session.DB(dbs).C("admin").Find(bson.M{"uname": username}).One(&admin); err != nil {
			break
		}
	}

	email := data["email"]
	pass, err := bcrypt.GenerateFromPassword([]byte(data["password"]), bcrypt.DefaultCost)
	if err != nil {
		HandleError(w, err)
		return
	}

	if err := uc.session.DB(dbs).C("admin").Find(bson.M{"email": email}).One(&admin); err == nil {
		//email already exists
		response = getResponse(500, "fail", "Email already exists")
		json.NewEncoder(w).Encode(response)
		return
	}

	admin = models.Admin{
		Name:         name,
		UName:        username,
		Email:        email,
		Password:     string(pass),
		RegisterDate: time.Now(),
		LastLogin:    time.Now(),
	}

	admin.ID = bson.NewObjectId()

	if err := uc.session.DB(dbs).C("admin").Insert(admin); err != nil {
		response = getResponse(500, "fail", "Internal server error")
		json.NewEncoder(w).Encode(response)
		return
	}

	response = getResponse(201, "success", "User created")
	json.NewEncoder(w).Encode(response)
}

func (uc UserController) Feed(w http.ResponseWriter, req *http.Request, s httprouter.Params) {
	cookie := getCookieByName(w, req, "jwtadmin")

	user := models.Admin{}
	token, err := jwt.ParseWithClaims(cookie, &jwt.StandardClaims{}, func(token *jwt.Token) (interface{}, error) {
		return []byte(SecretKey), nil
	})

	if err != nil {
		fmt.Println("token error")
		return
	}

	claims := token.Claims.(*jwt.StandardClaims)
	uid := bson.ObjectIdHex(claims.Issuer)
	if err := uc.session.DB(dbs).C("admin").Find(bson.M{"_id": uid}).One(&user); err != nil {
		//user doesn't exist
		fmt.Println("user dont exist")
		return

	}

	key := req.URL.Path
	data := models.AdminData{
		Admin: user,
		UKey:  key,
	}

	err = view.ExecuteTemplate(w, "base.html", data)
	HandleError(w, err)

}

func (uc UserController) CreateBuilding(w http.ResponseWriter, req *http.Request, s httprouter.Params) {
	cookie := getCookieByName(w, req, "jwtadmin")
	response := models.Response{}
	//user := models.Admin{}
	_, err := jwt.ParseWithClaims(cookie, &jwt.StandardClaims{}, func(token *jwt.Token) (interface{}, error) {
		return []byte(SecretKey), nil
	})

	if err != nil {
		fmt.Println("token error")
		return
	}

	buildingName := strings.ToLower(req.FormValue("buildingName"))
	buildingLvl, err := strconv.Atoi(strings.ToLower(req.FormValue("buildingLvl")))
	foodReq, err := strconv.Atoi(strings.ToLower(req.FormValue("foodReq")))
	woodReq, err := strconv.Atoi(strings.ToLower(req.FormValue("woodReq")))
	ironReq, err := strconv.Atoi(strings.ToLower(req.FormValue("ironReq")))
	silverReq, err := strconv.Atoi(strings.ToLower(req.FormValue("silverReq")))
	nobleReq, err := strconv.Atoi(strings.ToLower(req.FormValue("nobleReq")))
	royalReq, err := strconv.Atoi(strings.ToLower(req.FormValue("royalReq")))
	bookOfWar, err := strconv.Atoi(strings.ToLower(req.FormValue("booksOfWar")))
	buildingReq1Name := strings.ToLower(req.FormValue("buildNameReq1"))
	buildingReq1Level, err := strconv.Atoi(strings.ToLower(req.FormValue("buildLevelReq1")))
	buildingReq2Name := strings.ToLower(req.FormValue("buildNameReq2"))
	buildingReq2Level, err := strconv.Atoi(strings.ToLower(req.FormValue("buildLevelReq2")))
	buildingReq3Name := strings.ToLower(req.FormValue("buildNameReq3"))
	buildingReq3Level, err := strconv.Atoi(strings.ToLower(req.FormValue("buildLevelReq3")))
	fmt.Println(buildingName, buildingLvl)

	b := models.Buildings{
		Buildings: models.Building{
			BuildingName: buildingName,
			BuildingLvl:  buildingLvl,
			FoodReq:      foodReq,
			WoodReq:      woodReq,
			IronReq:      ironReq,
			SilverReq:    silverReq,
			NobleBadge:   nobleReq,
			RoyalBadge:   royalReq,
			BookOfWar:    bookOfWar,
			BuildingReq: []models.UserBuilding{
				models.UserBuilding{
					BuildingName: buildingReq1Name,
					BuildingLvl:  buildingReq1Level,
				},
				models.UserBuilding{
					BuildingName: buildingReq2Name,
					BuildingLvl:  buildingReq2Level,
				},
				models.UserBuilding{
					BuildingName: buildingReq3Name,
					BuildingLvl:  buildingReq3Level,
				},
			},
		},
	}
	b.ID = bson.NewObjectId()

	//json.NewDecoder(req.Body).Decode(&user)
	if err := uc.session.DB(dbs).C("buildings").Insert(b); err != nil {
		response = getResponse(500, "fail", "Internal server error")
		json.NewEncoder(w).Encode(response)
		return
	}

	response = getResponse(201, "success", "building created")
	json.NewEncoder(w).Encode(response)
	return

}

func (uc UserController) CreateHero(w http.ResponseWriter, req *http.Request, s httprouter.Params) {
	cookie := getCookieByName(w, req, "jwtadmin")
	response := models.Response{}
	//user := models.Admin{}
	_, err := jwt.ParseWithClaims(cookie, &jwt.StandardClaims{}, func(token *jwt.Token) (interface{}, error) {
		return []byte(SecretKey), nil
	})

	if err != nil {
		fmt.Println("token error")
		return
	}

	heroName := strings.ToLower(req.FormValue("heroName"))
	starLvl, err := strconv.Atoi(strings.ToLower(req.FormValue("starLvl")))
	skillName := strings.ToLower(req.FormValue("skillName"))
	skillLvl, err := strconv.Atoi(strings.ToLower(req.FormValue("skillLvl")))
	skillBonus, err := strconv.Atoi(strings.ToLower(req.FormValue("skillBonus"))) //number
	rssBonus := strings.ToLower(req.FormValue("rssBonus"))                        //rss affected
	typeBonus := strings.ToLower(req.FormValue("typeBonus"))                      // construction/research

	skillName2 := strings.ToLower(req.FormValue("skillName2"))
	skillLvl2, err := strconv.Atoi(strings.ToLower(req.FormValue("skillLvl2")))
	skillBonus2, err := strconv.Atoi(strings.ToLower(req.FormValue("skillBonus2"))) //number
	rssBonus2 := strings.ToLower(req.FormValue("rssBonus2"))                        //rss affected
	typeBonus2 := strings.ToLower(req.FormValue("typeBonus2"))                      // construction/research

	skillName3 := strings.ToLower(req.FormValue("skillName3"))
	skillLvl3, err := strconv.Atoi(strings.ToLower(req.FormValue("skillLvl3")))
	skillBonus3, err := strconv.Atoi(strings.ToLower(req.FormValue("skillBonus3"))) //number
	rssBonus3 := strings.ToLower(req.FormValue("rssBonus3"))                        //rss affected
	typeBonus3 := strings.ToLower(req.FormValue("typeBonus3"))                      // construction/research

	skillName4 := strings.ToLower(req.FormValue("skillName4"))
	skillLvl4, err := strconv.Atoi(strings.ToLower(req.FormValue("skillLvl4")))
	skillBonus4, err := strconv.Atoi(strings.ToLower(req.FormValue("skillBonus4"))) //number
	rssBonus4 := strings.ToLower(req.FormValue("rssBonus4"))                        //rss affected
	typeBonus4 := strings.ToLower(req.FormValue("typeBonus4"))                      // construction/research

	skillName5 := strings.ToLower(req.FormValue("skillName5"))
	skillLvl5, err := strconv.Atoi(strings.ToLower(req.FormValue("skillLvl5")))
	skillBonus5, err := strconv.Atoi(strings.ToLower(req.FormValue("skillBonus5"))) //number
	rssBonus5 := strings.ToLower(req.FormValue("rssBonus5"))                        //rss affected
	typeBonus5 := strings.ToLower(req.FormValue("typeBonus5"))                      // construction/research

	skillName6 := strings.ToLower(req.FormValue("skillName6"))
	skillLvl6, err := strconv.Atoi(strings.ToLower(req.FormValue("skillLvl6")))
	skillBonus6, err := strconv.Atoi(strings.ToLower(req.FormValue("skillBonus6"))) //number
	rssBonus6 := strings.ToLower(req.FormValue("rssBonus6"))                        //rss affected
	typeBonus6 := strings.ToLower(req.FormValue("typeBonus6"))                      // construction/research

	hero := models.Hero{}

	if err := uc.session.DB(dbs).C("heroes").Find(bson.M{"heroName": heroName}).One(&hero); err != nil {

		h := models.Hero{
			HeroName: heroName,
			HeroBuffs: []models.HeroBuff{
				models.HeroBuff{
					StarLvl: starLvl,
					SkillBuff: []models.Skills{
						models.Skills{
							SkillName:      skillName,
							SkillBonusType: typeBonus,
							SkillBonusRss:  rssBonus,
							SkillBonusDetail: []models.SkillBonus{
								models.SkillBonus{
									SkillLvl:   skillLvl,
									SkillBonus: skillBonus,
								},
							},
						},
						models.Skills{
							SkillName:      skillName2,
							SkillBonusType: typeBonus2,
							SkillBonusRss:  rssBonus2,
							SkillBonusDetail: []models.SkillBonus{
								models.SkillBonus{
									SkillLvl:   skillLvl2,
									SkillBonus: skillBonus2,
								},
							},
						},
						models.Skills{
							SkillName:      skillName3,
							SkillBonusType: typeBonus3,
							SkillBonusRss:  rssBonus3,
							SkillBonusDetail: []models.SkillBonus{
								models.SkillBonus{
									SkillLvl:   skillLvl3,
									SkillBonus: skillBonus3,
								},
							},
						},
						models.Skills{
							SkillName:      skillName4,
							SkillBonusType: typeBonus4,
							SkillBonusRss:  rssBonus4,
							SkillBonusDetail: []models.SkillBonus{
								models.SkillBonus{
									SkillLvl:   skillLvl4,
									SkillBonus: skillBonus4,
								},
							},
						},
						models.Skills{
							SkillName:      skillName5,
							SkillBonusType: typeBonus5,
							SkillBonusRss:  rssBonus5,
							SkillBonusDetail: []models.SkillBonus{
								models.SkillBonus{
									SkillLvl:   skillLvl5,
									SkillBonus: skillBonus5,
								},
							},
						},
						models.Skills{
							SkillName:      skillName6,
							SkillBonusType: typeBonus6,
							SkillBonusRss:  rssBonus6,
							SkillBonusDetail: []models.SkillBonus{
								models.SkillBonus{
									SkillLvl:   skillLvl6,
									SkillBonus: skillBonus6,
								},
							},
						},
					},
				},
			},
		}

		h.ID = bson.NewObjectId()
		if err := uc.session.DB(dbs).C("heroes").Insert(h); err != nil {
			response = getResponse(500, "fail", "Internal server error")
			json.NewEncoder(w).Encode(response)
			return
		}

		response = getResponse(201, "success", "hero created")
		json.NewEncoder(w).Encode(response)
		return
	}

}

func (uc UserController) CreateGear(w http.ResponseWriter, req *http.Request, s httprouter.Params) {
	cookie := getCookieByName(w, req, "jwtadmin")
	response := models.Response{}
	//user := models.Admin{}
	_, err := jwt.ParseWithClaims(cookie, &jwt.StandardClaims{}, func(token *jwt.Token) (interface{}, error) {
		return []byte(SecretKey), nil
	})

	if err != nil {
		fmt.Println("token error")
		return
	}

	//gearSetName := strings.ToLower(req.FormValue("gearSet"))
	gearName := strings.ToLower(req.FormValue("gearName"))
	gearLvl, err := strconv.Atoi(req.FormValue("gearLvl"))
	gearBonus1, err := strconv.ParseFloat(req.FormValue("bonus1"), 64)
	gearBonus1Rss := strings.ToLower(req.FormValue("bonus1rss"))
	gearBonus2, err := strconv.ParseFloat(req.FormValue("bonus2"), 64)
	gearBonus2Rss := strings.ToLower(req.FormValue("bonus2rss"))
	gearBonus3, err := strconv.ParseFloat(req.FormValue("bonus3"), 64)
	gearBonus3Rss := strings.ToLower(req.FormValue("bonus3rss"))

	setName := models.Gear{}

	if err := uc.session.DB(dbs).C("gear").Find(bson.M{"gearName": gearName, "gearLvl": gearLvl}).One(&setName); err != nil {

		/*g := models.Gear{
			SetName: gearSetName,
			GearDetails: []models.GearDetail{
				models.GearDetail{
					GearName:  gearName,
					GearLvl:   gearLvl,
					Bonus1:    gearBonus1,
					Bonus1Rss: gearBonus1Rss,
					Bonus2:    gearBonus2,
					Bonus2Rss: gearBonus2Rss,
					Bonus3:    gearBonus3,
					Bonus3Rss: gearBonus3Rss,
				},
				models.GearDetail{
					GearName:  gearName2,
					GearLvl:   gearLvl2,
					Bonus1:    gearBonus12,
					Bonus1Rss: gearBonus1Rss2,
					Bonus2:    gearBonus22,
					Bonus2Rss: gearBonus2Rss2,
					Bonus3:    gearBonus32,
					Bonus3Rss: gearBonus3Rss2,
				},
				models.GearDetail{
					GearName:  gearName3,
					GearLvl:   gearLvl3,
					Bonus1:    gearBonus13,
					Bonus1Rss: gearBonus1Rss3,
					Bonus2:    gearBonus23,
					Bonus2Rss: gearBonus2Rss3,
					Bonus3:    gearBonus33,
					Bonus3Rss: gearBonus3Rss3,
				},
				models.GearDetail{
					GearName:  gearName4,
					GearLvl:   gearLvl4,
					Bonus1:    gearBonus14,
					Bonus1Rss: gearBonus1Rss4,
					Bonus2:    gearBonus24,
					Bonus2Rss: gearBonus2Rss4,
					Bonus3:    gearBonus34,
					Bonus3Rss: gearBonus3Rss4,
				},
				models.GearDetail{
					GearName:  gearName5,
					GearLvl:   gearLvl5,
					Bonus1:    gearBonus15,
					Bonus1Rss: gearBonus1Rss5,
					Bonus2:    gearBonus25,
					Bonus2Rss: gearBonus2Rss5,
					Bonus3:    gearBonus35,
					Bonus3Rss: gearBonus3Rss5,
				},
				models.GearDetail{
					GearName:  gearName6,
					GearLvl:   gearLvl6,
					Bonus1:    gearBonus16,
					Bonus1Rss: gearBonus1Rss6,
					Bonus2:    gearBonus26,
					Bonus2Rss: gearBonus2Rss6,
					Bonus3:    gearBonus36,
					Bonus3Rss: gearBonus3Rss6,
				},
			},
		}*/

		g := models.Gear{
			GearName: gearName,
			GearDetails: []models.GearDetail{
				models.GearDetail{
					GearLvl:   gearLvl,
					Bonus1:    gearBonus1,
					Bonus1Rss: gearBonus1Rss,
					Bonus2:    gearBonus2,
					Bonus2Rss: gearBonus2Rss,
					Bonus3:    gearBonus3,
					Bonus3Rss: gearBonus3Rss,
				},
			},
		}

		g.ID = bson.NewObjectId()
		if err := uc.session.DB(dbs).C("gear").Insert(g); err != nil {
			response = getResponse(500, "fail", "Internal server error")
			json.NewEncoder(w).Encode(response)
			return
		}

		response = getResponse(201, "success", "gear created")
		json.NewEncoder(w).Encode(response)
		return
	}

}
