package api

import (
	"encoding/xml"
	"errors"
	"net/http"

	"github.com/gin-gonic/gin"
	"github.com/slotopol/server/config"
	. "github.com/slotopol/server/model"
)

const (
	AEC_club_new_nobind   = 7001
	AEC_club_new_noaccess = 7002
	AEC_club_new_insert   = 7003
)

// Check if the user is in a club.
func ApiClubIs(c *gin.Context) {
	var ret struct {
		XMLName xml.Name `json:"-" yaml:"-" xml:"ret"`
		Is      bool     `json:"is" yaml:"is" xml:"is,attr"`
	}

	ret.Is = GetClub(c) != nil
	RetOk(c, ret)
}

// Get club info.
func ApiClubInfo(c *gin.Context) {
	cl := GetClub(c)
	if cl == nil {
		Ret404(c, AEC_club_info_noclub, ErrClubNotFound)
		return
	}

	cl.mu.RLock()
	var ret = ClubData{
		CID:   cl.CID,
		Name:  cl.Name,
		Bank:  cl.Bank,
		Fund:  cl.Fund,
		Lock:  cl.Lock,
	}
	cl.mu.RUnlock()

	RetOk(c, ret)
}

// Rename club (admin only).
func ApiClubRename(c *gin.Context) {
	var arg struct {
		XMLName xml.Name `json:"-" yaml:"-" xml:"arg"`
		Name    string   `json:"name" yaml:"name" xml:"name,attr"`
	}

	if err := c.ShouldBind(&arg); err != nil {
		Ret400(c, AEC_club_rename_nobind, err)
		return
	}

	cl := GetClub(c)
	if cl == nil {
		Ret404(c, AEC_club_rename_noclub, ErrClubNotFound)
		return
	}

	uid, al := MustAuth(c)
	if al&ALadmin == 0 {
		Ret403(c, AEC_club_rename_noaccess, ErrNoAccess)
		return
	}

	cl.mu.Lock()
	cl.Name = arg.Name
	cd := ClubData{
		CID:  cl.CID,
		Name: cl.Name,
	}
	cl.mu.Unlock()

	if _, err := config.XormStorage.ID(cl.CID).Cols("name").Update(&cd); err != nil {
		Ret500(c, AEC_club_rename_update, err)
		return
	}

	Ret204(c)
}

// Admin-only: create a new club.
func ApiClubNew(c *gin.Context) {
	var err error

	var arg struct {
		XMLName xml.Name `json:"-" yaml:"-" xml:"arg"`
		Name    string   `json:"name" yaml:"name" xml:"name,attr" form:"name" binding:"required"`
	}
	var ret struct {
		XMLName xml.Name `json:"-" yaml:"-" xml:"ret"`
		CID     uint64   `json:"cid" yaml:"cid" xml:"cid,attr"`
	}

	if err = c.ShouldBind(&arg); err != nil {
		Ret400(c, AEC_club_new_nobind, err)
		return
	}

	uid, al := MustAuth(c)
	if al&ALadmin == 0 {
		Ret403(c, AEC_club_new_noaccess, ErrNoAccess)
		return
	}

	cd := ClubData{
		Name: arg.Name,
	}

	if _, err := config.XormStorage.Insert(&cd); err != nil {
		Ret500(c, AEC_club_new_insert, err)
		return
	}

	cl := NewClub(cd)
	Clubs.Set(cd.CID, cl)

	ret.CID = cd.CID
	RetOk(c, ret)
}

// List all clubs (admin only).
func ApiClubList(c *gin.Context) {
	_, al := MustAuth(c)
	if al&ALadmin == 0 {
		Ret403(c, AEC_club_list_noaccess, ErrNoAccess)
		return
	}

	var list []ClubData
	err := config.XormStorage.Find(&list)
	if err != nil {
		Ret500(c, AEC_club_list_query, err)
		return
	}

	RetOk(c, list)
}

// Cashin funds to club (admin only).
func ApiClubCashin(c *gin.Context) {
	var arg struct {
		XMLName xml.Name `json:"-" yaml:"-" xml:"arg"`
		Amount  int64    `json:"amount" yaml:"amount" xml:"amount,attr"`
	}

	if err := c.ShouldBind(&arg); err != nil {
		Ret400(c, AEC_club_cashin_nobind, err)
		return
	}

	cl := GetClub(c)
	if cl == nil {
		Ret404(c, AEC_club_cashin_noclub, ErrClubNotFound)
		return
	}

	uid, al := MustAuth(c)
	if al&ALadmin == 0 {
		Ret403(c, AEC_club_cashin_noaccess, ErrNoAccess)
		return
	}

	if arg.Amount <= 0 {
		Ret400(c, AEC_club_cashin_invalid, errors.New("invalid amount"))
		return
	}

	cl.mu.Lock()
	cl.Bank += arg.Amount
	cl.mu.Unlock()

	cd := ClubData{
		CID:  cl.CID,
		Bank: cl.Bank,
	}
	if _, err := config.XormStorage.ID(cl.CID).Cols("bank").Update(&cd); err != nil {
		Ret500(c, AEC_club_cashin_update, err)
		return
	}

	BankLogAdd(cl.CID, uid, "admin.cashin", arg.Amount)

	Ret204(c)
}