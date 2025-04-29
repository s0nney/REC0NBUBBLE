package config

type Config struct {
	App struct {
		Name        string `yaml:"name"`
		Environment string `yaml:"environment"`
		Port        int    `yaml:"port"`
	} `yaml:"app"`

	Security struct {
		RateLimit struct {
			Requests      int `yaml:"requests"`
			PerMinute     int `yaml:"per_minute"`
			CaptchaFails  int `yaml:"captcha_fails"`
			BlockDuration int `yaml:"block_duration"`
		} `yaml:"rate_limit"`
		Captcha struct {
			Enabled       bool `yaml:"enabled"`
			MaxDifficulty int  `yaml:"max_difficulty"`
			FailsPerLevel int  `yaml:"fails_per_level"`
		} `yaml:"captcha"`
		Session struct {
			CookieSecret string `yaml:"cookie_secret"`
			MaxAge       int    `yaml:"max_age"`
			Secure       bool   `yaml:"secure"`
			HTTPOnly     bool   `yaml:"http_only"`
		} `yaml:"session"`
	} `yaml:"security"`

	Templates struct {
		Directory string `yaml:"directory"`
	} `yaml:"templates"`

	Static struct {
		Directory string `yaml:"directory"`
	} `yaml:"static"`
}
