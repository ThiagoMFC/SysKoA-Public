package models

import (
	"time"

	"gopkg.in/mgo.v2/bson"
)

type Response struct {
	Code     int    `json:"code" bson:"code"`
	Response string `json:"response" bson:"response"`
	//Data     Message
	Message string `json:"message" bson:"message"`
}

//----------------------------------------------------------------------------
//User struct
type User struct {
	ID            bson.ObjectId  `json:"id" bson:"_id"`
	Name          string         `json:"name" bson:"name"`
	UName         string         `json:"uname" bson:"uname"`
	Email         string         `json:"email" bson:"email"`
	Password      string         `json:"-" bson:"password"`
	UserBuildings []UserBuilding `json:"userBuildings" bson:"userBuildings"`
	UserResources UserRss        `json:"userResources" bson:"userResources"`
	UserHeroes    []UserHero     `json:"userHeroes" bson:"userHeroes"`
	UserGear      UserGear       `json:"userGear" bson:"userGear"`
	UserFarms     []UserFarm     `json:"userFarms" bson:"userFarms"`
	//Gender       string    `json:"gender" bson:"gender"`
	//DateOfBirth  time.Time `json:"birthDate" bson:"birthDate"`
	RegisterDate time.Time `json:"-" bson:"regDate"`
	LastLogin    time.Time `json:"-" bson:"lLogin"`
}

type UserBuilding struct {
	BuildingName string `json:"buildingName" bson:"buildingName"`
	BuildingLvl  int    `json:"buildingLvl" bson:"buildingLvl"`
}

type UserRss struct {
	OpenFood   int    `json:"openFood" bson:"openFood"`
	OpenWood   int    `json:"openWood" bson:"openWood"`
	OpenIron   int    `json:"openIron" bson:"openIron"`
	OpenSilver int    `json:"openSilver" bson:"openSilver"`
	FoodItem   Food   `json:"foodItem" bson:"foodItem"`
	WoodItem   Wood   `json:"woodItem" bson:"woodItem"`
	IronItem   Iron   `json:"ironItem" bson:"ironItem"`
	SilverItem Silver `json:"silverItem" bson:"silverItem"`
	NobleBadge int    `json:"nobleBadge" bson:"nobleBadge"`
	RoyalBadge int    `json:"royalBadge" bson:"royalBadge"`
	BookOfWar  int    `json:"bookOfWar" bson:"bookOfWar"`
}

type UserHero struct {
	HeroName    string           `json:"heroName" bson:"heroName"`
	HeroLvl     int              `json:"heroLvl" bson:"heroLvl"`
	HeroStarLvl int              `json:"heroStarLvl" bson:"heroStarLvl"`
	HeroSkills  []UserHeroSkills `json:"heroSkills" bson:"heroSkills"`
	Appointed   bool             `json:"appointed" bson:"appointed"`
}

type UserHeroSkills struct {
	SkillName string `json:"skillName" bson:"skillName"`
	SkillLvl  int    `json:"skillLvl" bson:"skillLvl"`
}

type UserGear struct {
	Head      string `json:"head" bson:"head"`
	HeadLvl   int    `json:"headLvl" bson:"headLvl"`
	Neck      string `json:"neck" bson:"neck"`
	NeckLvl   int    `json:"neckLvl" bson:"neckLvl"`
	Torso     string `json:"torso" bson:"torso"`
	TorsoLvl  int    `json:"torsoLvl" bson:"torsoLvl"`
	Weapon    string `json:"weapon" bson:"weapon"`
	WeaponLvl int    `json:"weaponLvl" bson:"weaponLvl"`
	Ring      string `json:"ring" bson:"ring"`
	RingLvl   int    `json:"ringLvl" bson:"ringLvl"`
	Boots     string `json:"boots" bson:"boots"`
	BootsLvl  int    `json:"bootsLvl" bson:"bootsLvl"`
}

type UserFarm struct {
	FarmName      string  `json:"farmName" bson:"farmName"`
	FarmResources UserRss `json:"farmResources" bson:"farmResources"`
}

//-----------------------------------------------------------------------------

type Gear struct {
	ID          bson.ObjectId `json:"id" bson:"_id"`
	GearName    string        `json:"gearName" bson:"gearName"`
	GearDetails []GearDetail  `json:"gearDetails" bson:"gearDetails"`
}

type GearDetail struct {
	GearLvl   int     `json:"gearLvl" bson:"gearLvl"`
	Bonus1    float64 `json:"bonus1" bson:"bonus1"`
	Bonus1Rss string  `json:"bonus1Rss" bson:"bonus1Rss"`
	Bonus2    float64 `json:"bonus2" bson:"bonus2"`
	Bonus2Rss string  `json:"bonus2Rss" bson:"bonus2Rss"`
	Bonus3    float64 `json:"bonus3" bson:"bonus3"`
	Bonus3Rss string  `json:"bonus3Rss" bson:"bonus3Rss"`
}

//-----------------------------------------------------------------------------

type Hero struct {
	ID        bson.ObjectId `json:"id" bson:"_id"`
	HeroName  string        `json:"heroName" bson:"heroName"`
	HeroBuffs []HeroBuff    `json:"heroBuff" bson:"heroBuff"`
}

type HeroBuff struct {
	StarLvl   int      `json:"starLvl" bson:"starLvl"`
	SkillBuff []Skills `json:"skills" bson:"skills"`
}

type Skills struct {
	SkillName        string       `json:"skillName" bson:"skillName"`
	SkillBonusType   string       `json:"skillBonusType" bson:"skillBonusType"`
	SkillBonusRss    string       `json:"skillBonusRss" bson:"skillBonusRss"`
	SkillBonusDetail []SkillBonus `json:"skillBonusDetail" bson:"skillBonusDetail"`
}

type SkillBonus struct {
	SkillLvl   int `json:"skillLvl" bson:"skillLvl"`
	SkillBonus int `json:"skillBonus" bson:"skillBonus"`
}

//-----------------------------------------------------------------------------
//Building base struct
type Building struct {
	BuildingName string         `json:"buildingName" bson:"buildingName"`
	BuildingLvl  int            `json:"buildingLvl" bson:"buildingLvl"`
	FoodReq      int            `json:"foodReq" bson:"foodReq"`
	WoodReq      int            `json:"woodReq" bson:"woodReq"`
	IronReq      int            `json:"ironReq" bson:"ironReq"`
	SilverReq    int            `json:"silverReq" bson:"silverReq"`
	NobleBadge   int            `json:"nobleBadge" bson:"nobleBadge"`
	RoyalBadge   int            `json:"royalBadge" bson:"royalBadge"`
	BookOfWar    int            `json:"bookOfWar" bson:"bookOfWar"`
	BuildingReq  []UserBuilding `json:"buildingReq" bson:"buildingReq"`
}

type Buildings struct {
	ID        bson.ObjectId `json:"-" bson:"_id"`
	Buildings Building      `json:"buildings" bson:"buildings"`
}

//--------------------------------------------------------------------------------
type Upgrade struct {
	FoodDiscountPercentage   float64     `json:"foodDiscountPercentage" bson:"foodDiscountPercentage"`
	WoodDiscountPercentage   float64     `json:"woodDiscountPercentage" bson:"woodDiscountPercentage"`
	IronDiscountPercentage   float64     `json:"ironDiscountPercentage" bson:"foodDiscountPercentage"`
	SilverDiscountPercentage float64     `json:"silverDiscountPercentage" bson:"silverDiscountPercentage"`
	FoodDiscount             float64     `json:"foodDiscount" bson:"foodDiscount"`
	WoodDiscount             float64     `json:"woodDiscount" bson:"woodDiscount"`
	IronDiscount             float64     `json:"ironDiscount" bson:"ironDiscount"`
	SilverDiscount           float64     `json:"silverDiscount" bson:"silverDiscount"`
	UserRes                  UserRss     `json:"userRes" bson:"userRes"`
	UserFarmRes              []UserFarm  `json:"userFarms" bson:"userFarms"`
	UpgradeableBuildings     []Buildings `json:"buildings" bson:"buildings"`
}

//-------------------------------------------------------------------------------
type Food struct {
	Food1k    int `json:"food1k" bson:"food1k"`
	Food3k    int `json:"food3k" bson:"food3k"`
	Food5k    int `json:"food5k" bson:"food5k"`
	Food10k   int `json:"food10k" bson:"food10k"`
	Food30k   int `json:"food30k" bson:"food30k"`
	Food50k   int `json:"food50k" bson:"food50k"`
	Food150k  int `json:"food150k" bson:"food150k"`
	Food500k  int `json:"food500k" bson:"food500k"`
	Food1500k int `json:"food1500k" bson:"food1500k"`
}

type Wood struct {
	Wood1k    int `json:"wood1k" bson:"wood1k"`
	Wood3k    int `json:"wood3k" bson:"wood3k"`
	Wood5k    int `json:"wood5k" bson:"wood5k"`
	Wood10k   int `json:"wood10k" bson:"wood10k"`
	Wood30k   int `json:"wood30k" bson:"wood30k"`
	Wood50k   int `json:"wood50k" bson:"wood50k"`
	Wood150k  int `json:"wood150k" bson:"wood150k"`
	Wood500k  int `json:"wood500k" bson:"wood500k"`
	Wood1500k int `json:"wood1500k" bson:"wood1500k"`
}

type Iron struct {
	Iron200  int `json:"iron200" bson:"iron200"`
	Iron600  int `json:"iron600" bson:"iron600"`
	Iron1k   int `json:"iron1k" bson:"iron1k"`
	Iron2k   int `json:"iron2k" bson:"iron2k"`
	Iron6k   int `json:"iron6k" bson:"iron6k"`
	Iron10k  int `json:"iron10k" bson:"iron10k"`
	Iron30k  int `json:"iron30k" bson:"iron30k"`
	Iron100k int `json:"iron100k" bson:"iron100k"`
	Iron300k int `json:"iron300k" bson:"iron300k"`
}

type Silver struct {
	Silver50   int `json:"silver50" bson:"silver50"`
	Silver150  int `json:"silver150" bson:"silver150"`
	Silver250  int `json:"silver250" bson:"silver250"`
	Silver500  int `json:"silver500" bson:"silver500"`
	Silver1500 int `json:"silver1500" bson:"silver1500"`
	Silver2500 int `json:"silver2500" bson:"silver2500"`
	Silver25k  int `json:"silver25k" bson:"silver25k"`
	Silver75k  int `json:"silver75k" bson:"silver75k"`
}

//-----------------------------------------------------------------------------------
type Admin struct {
	ID       bson.ObjectId `json:"id" bson:"_id"`
	Name     string        `json:"name" bson:"name"`
	UName    string        `json:"uname" bson:"uname"`
	Email    string        `json:"email" bson:"email"`
	Password string        `json:"-" bson:"password"`
	//Gender       string    `json:"gender" bson:"gender"`
	//DateOfBirth  time.Time `json:"birthDate" bson:"birthDate"`
	RegisterDate time.Time `json:"regDate" bson:"regDate"`
	LastLogin    time.Time `json:"lLogin" bson:"lLogin"`
}

//store user info to send between pages
type AdminData struct {
	Admin
	UKey string
}
