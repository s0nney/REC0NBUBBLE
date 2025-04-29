package handlers

import (
	"net/http"

	"REC0NBUBBLE/internal/config"

	"github.com/gin-gonic/gin"
)

func HandleHome(c *gin.Context) {
	cfg := c.MustGet("config").(*config.Config)
	data := gin.H{
		"title": "REC0NBUBBLE",
	}

	if cfg.Security.Captcha.Enabled {
		GenerateCaptcha(c)
		captchaProblem, _ := c.Get("captcha_problem")
		captchaDifficulty, _ := c.Get("captcha_difficulty")
		captchaOptions, _ := c.Get("captcha_options")
		data["captchaProblem"] = captchaProblem
		data["captchaDifficulty"] = captchaDifficulty
		data["captchaOptions"] = captchaOptions
	}

	c.HTML(http.StatusOK, "home.html", data)
}
